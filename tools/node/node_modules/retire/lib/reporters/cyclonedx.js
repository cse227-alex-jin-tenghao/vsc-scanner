"use strict";
/*jshint esversion: 6 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const retire = __importStar(require("../retire"));
const fs = __importStar(require("fs"));
const uuid_1 = require("uuid");
const utils_1 = require("./utils");
function configureCycloneDXLogger(logger, writer, config, hash) {
    let vulnsFound = false;
    const finalResults = {
        version: retire.version,
        start: new Date(),
        data: [],
        messages: [],
        errors: [],
    };
    logger.info = finalResults.messages.push;
    logger.debug = config.verbose
        ? finalResults.messages.push
        : () => {
            return;
        };
    logger.warn = logger.error = finalResults.errors.push;
    logger.logVulnerableDependency = function (finding) {
        vulnsFound = true;
        finalResults.data.push(finding);
    };
    logger.logDependency = function (finding) {
        if (finding.results.length > 0) {
            finalResults.data.push(finding);
        }
    };
    logger.close = function (callback) {
        const write = vulnsFound ? writer.err : writer.out;
        const seen = new Set();
        const components = finalResults.data
            .filter((d) => d.results.length > 0)
            .map((r) => r.results
            .map((dep) => {
            dep.version = (dep.version.split('.').length >= 3 ? dep.version : dep.version + '.0').replace(/-/g, '.');
            const filepath = r.file;
            let hashes = '';
            if (filepath) {
                const file = fs.readFileSync(filepath);
                hashes = `
          <hashes>
            <hash alg="MD5">${hash.md5(file)}</hash>
            <hash alg="SHA-1">${hash.sha1(file)}</hash>
            <hash alg="SHA-256">${hash.sha256(file)}</hash>
            <hash alg="SHA-512">${hash.sha512(file)}</hash>
          </hashes>`;
            }
            const purl = (0, utils_1.generatePURL)(dep);
            if (seen.has(purl))
                return '';
            seen.add(purl);
            const nameParts = dep.component.split('/').reverse();
            return `
    <component type="library">
      <name>${nameParts[0]}</name>${nameParts.length > 1 ? `\n      <group>${nameParts[1]}</group>` : ''}
      <version>${dep.version}</version>${hashes}
      <licenses>${mapLicenses(dep.licenses)}</licenses>
      <purl>${purl}</purl>
      <modified>false</modified>
    </component>`;
        })
            .join(''))
            .join('');
        write(`<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" serialNumber="urn:uuid:${(0, uuid_1.v4)()}" version="1">
  <metadata>
    <timestamp>${finalResults.start.toISOString()}</timestamp>
    <tools>
        <tool>
            <vendor>RetireJS</vendor>
            <name>retire.js</name>
            <version>${retire.version}</version>
        </tool>
    </tools>
  </metadata>
  <components>${components}
  </components>
</bom>`);
        writer.close(callback);
    };
}
function mapLicenses(licenses) {
    if (!licenses)
        return '';
    if (licenses.length == 0)
        return '';
    if (licenses[0] == 'commercial')
        return '<license><name>Commercial</name></license>';
    return `<expression>${licenses[0]}</expression>`;
}
exports.default = {
    configure: configureCycloneDXLogger,
};
