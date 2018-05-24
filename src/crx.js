/* global require, process, Buffer, module */
'use strict';

var fs = require("fs");
var path = require("path");
var join = path.join;
var crypto = require("crypto");
var RSA = require("node-rsa");
var archiver = require("archiver");
var Promise = require("es6-promise").Promise;
var resolve = require("./resolver.js");
var BufferBuilder = require('buffer-builder');

function ChromeExtension(attrs) {
  if ((this instanceof ChromeExtension) !== true) {
    return new ChromeExtension(attrs);
  }

  /*
   Defaults
   */
  this.appId = null;

  this.rootDirectory = '';

  this.publicKey = null;

  this.privateKey = null;

  this.codebase = null;

  this.path = null;

  this.src = '**';

  /*
  Copying attributes
   */
  for (var name in attrs) {
    this[name] = attrs[name];
  }

  this.loaded = false;
}

ChromeExtension.prototype = {

  /**
   * Packs the content of the extension in a crx file.
   *
   * @param {Buffer=} contentsBuffer
   * @returns {Promise}
   * @example
   *
   * crx.pack().then(function(crxContent){
   *  // do something with the crxContent binary data
   * });
   *
   */
  pack: function (contentsBuffer) {
    if (!this.loaded) {
      return this.load().then(this.pack.bind(this, contentsBuffer));
    }

    var selfie = this;
    var packP = [
      this.generatePublicKey(),
      contentsBuffer || selfie.loadContents()
    ];

    return Promise.all(packP).then(function(outputs){
      var publicKey = outputs[0];
      var contents = outputs[1];

      selfie.publicKey = publicKey;

      var signature = selfie.generateSignature(contents);

      return selfie.generatePackage(signature, publicKey, contents);
    });
  },

  /**
   * Loads extension manifest and copies its content to a workable path.
   *
   * @param {string=} path
   * @returns {Promise}
   */
  load: function (path) {
    var selfie = this;

    return resolve(path || selfie.rootDirectory)
      .then(function(metadata){
        selfie.path = metadata.path;
        selfie.src = metadata.src;

        var manifestPath = join(selfie.path, 'manifest.json')
        delete require.cache[manifestPath];

        selfie.manifest = require(manifestPath);
        selfie.loaded = true;

        return selfie;
      });
  },

  /**
   * Writes data into the extension workable directory.
   *
   * @deprecated
   * @param {string} path
   * @param {*} data
   * @returns {Promise}
   */
  writeFile: function (path, data) {
    var absPath = join(this.path, path);

    /* istanbul ignore next */
    return new Promise(function(resolve, reject){
      fs.writeFile(absPath, data, function (err) {
        if (err) {
          return reject(err);
        }

        resolve();
      });
    });
  },

  /**
   * Generates a public key.
   *
   * BC BREAK `this.publicKey` is not stored anymore (since 1.0.0)
   * BC BREAK callback parameter has been removed in favor to the promise interface.
   *
   * @returns {Promise} Resolves to {Buffer} containing the public key
   * @example
   *
   * crx.generatePublicKey(function(publicKey){
   *   // do something with publicKey
   * });
   */
  generatePublicKey: function () {
    var privateKey = this.privateKey;

    return new Promise(function(resolve, reject){
      if (!privateKey) {
        return reject('Impossible to generate a public key: privateKey option has not been defined or is empty.');
      }

      var key = new RSA(privateKey);

      resolve(key.exportKey('pkcs8-public-der'));
    });
  },

  /**
   * Generates a SHA1 package signature.
   *
   * BC BREAK `this.signature` is not stored anymore (since 1.0.0)
   *
   * @param {Buffer} contents
   * @returns {Buffer}
   */
  generateSignature: function (contents) {
    return new Buffer(
      crypto
        .createSign("sha1")
        .update(contents)
        .sign(this.privateKey),
      "binary"
    );
  },

  /**
   *
   * BC BREAK `this.contents` is not stored anymore (since 1.0.0)
   *
   * @returns {Promise}
   */
  loadContents: function () {
    var selfie = this;

    return new Promise(function(resolve, reject){
      var archive = archiver('zip');
      var contents = new BufferBuilder();

      if (!selfie.loaded) {
	      throw new Error('crx.load needs to be called first in order to prepare the workspace.');
      }

      archive.on('error', reject);

      /*
        TODO: Remove in v4.
        It will be better to resolve an archive object
        rather than fitting everything in memory.

        @see https://github.com/oncletom/crx/issues/61
      */
      archive.on('data', function (buf) {
        contents.appendBuffer(buf);
      });

      archive.on('finish', function () {
        resolve(contents.get());
      });

      archive
        .glob(selfie.src, {
          cwd: selfie.path,
          matchBase: true,
          ignore: ['*.pem', '.git', '*.crx']
        })
        .finalize();
    });
  },

  /**
   * Generates and returns a signed package from extension content.
   *
   * BC BREAK `this.package` is not stored anymore (since 1.0.0)
   *
   * @param {Buffer} signature
   * @param {Buffer} publicKey
   * @param {Buffer} contents
   * @returns {Buffer}
   */
  generatePackage: function (signature, publicKey, contents) {
    var keyLength = publicKey.length;
    var sigLength = signature.length;
    var zipLength = contents.length;
    var length = 16 + keyLength + sigLength + zipLength;

    var crx = new Buffer(length);

    crx.write("Cr24" + new Array(13).join("\x00"), "binary");

    crx[4] = 2;
    crx.writeUInt32LE(keyLength, 8);
    crx.writeUInt32LE(sigLength, 12);

    publicKey.copy(crx, 16);
    signature.copy(crx, 16 + keyLength);
    contents.copy(crx, 16 + keyLength + sigLength);

    return crx;
  },

  /**
   * Generates an appId from the publicKey.
   * Public key has to be set for this to work, otherwise an error is thrown.
   *
   * BC BREAK `this.appId` is not stored anymore (since 1.0.0)
   * BC BREAK introduced `publicKey` parameter as it is not stored any more since 2.0.0
   *
   * @param {Buffer|string} [publicKey] the public key to use to generate the app ID
   * @returns {string}
   */
  generateAppId: function (keyOrPath) {
    keyOrPath = keyOrPath || this.publicKey;

    if (typeof keyOrPath !== 'string' && !(keyOrPath instanceof Buffer)) {
      throw new Error('Public key is neither set, nor given');
    }

    // Handling Windows Path
    // Possibly to be moved in a different method
    if (typeof keyOrPath === 'string') {
      var charCode = keyOrPath.charCodeAt(0);

      // 65 (A) < charCode < 122 (z)
      if (charCode >= 65 && charCode <= 122 && keyOrPath[1] === ':') {
        keyOrPath = keyOrPath[0].toUpperCase() + keyOrPath.slice(1);

        // TODO move to Buffer.from when drop old Node versions in crx@4
        /* istanbul ignore next */
        keyOrPath = ('from' in Buffer)
          ? Buffer.from(keyOrPath, "utf-16le")
          : new Buffer(keyOrPath, "utf-16le");
      }
    }

    return crypto
      .createHash("sha256")
      .update(keyOrPath)
      .digest()
      .toString("hex")
      .split("")
      .map(function(x) { return (parseInt(x, 16) + 0x0A).toString(26); })
      .join("")
      .slice(0, 32);
  },

  /**
   * Generates an updateXML file from the extension content.
   *
   * BC BREAK `this.updateXML` is not stored anymore (since 1.0.0)
   *
   * @returns {Buffer}
   */
  generateUpdateXML: function () {
    if (!this.codebase) {
      throw new Error("No URL provided for update.xml.");
    }

    return new Buffer(
      "<?xml version='1.0' encoding='UTF-8'?>\n" +
      "<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>\n" +
      "  <app appid='" + (this.appId || this.generateAppId()) + "'>\n" +
      "    <updatecheck codebase='" + this.codebase + "' version='" + this.manifest.version + "' />\n" +
      "  </app>\n" +
      "</gupdate>"
    );
  }
};

module.exports = ChromeExtension;
