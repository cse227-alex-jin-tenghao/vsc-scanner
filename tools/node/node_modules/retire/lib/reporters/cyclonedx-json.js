"use strict";
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
const path = __importStar(require("path"));
function configureCycloneDXJSONLogger(logger, writer, config, hash) {
    let vulnsFound = false;
    const finalResults = {
        version: retire.version,
        start: new Date().toISOString(),
        data: [],
        messages: [],
        errors: [],
    };
    logger.info = finalResults.messages.push;
    logger.debug = config.verbose
        ? finalResults.messages.push
        : function () {
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
        const seen = new Map();
        const components = finalResults.data
            .filter((d) => d.results)
            .map((r) => r.results
            .map((dep) => {
            dep.version = (dep.version.split('.').length >= 3 ? dep.version : dep.version + '.0').replace(/-/g, '.');
            let hashes;
            const filepath = r.file;
            const properties = [];
            if (filepath) {
                const file = fs.readFileSync(filepath);
                const relativePath = path.relative(process.cwd(), filepath);
                properties.push({ name: 'location', value: relativePath });
                hashes = [
                    { alg: 'MD5', content: hash.md5(file) },
                    { alg: 'SHA-1', content: hash.sha1(file) },
                    { alg: 'SHA-256', content: hash.sha256(file) },
                    { alg: 'SHA-512', content: hash.sha512(file) },
                ];
            }
            const purl = (0, utils_1.generatePURL)(dep);
            const existing = seen.get(purl);
            if (existing) {
                const missing = properties.filter((p) => !existing.properties.some((ep) => ep.value === p.value));
                existing.properties.push(...missing);
                return undefined;
            }
            const nameParts = dep.component.split('/').reverse();
            const result = {
                type: 'library',
                name: nameParts[0],
                group: nameParts[1],
                version: dep.version,
                purl: purl,
                hashes: hashes,
                licenses: mapLicenses(dep.licenses),
                properties,
            };
            seen.set(purl, result);
            return result;
        })
            .filter((x) => x != undefined))
            .reduce((a, b) => a.concat(b), []);
        write(JSON.stringify({
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            serialNumber: `urn:uuid:${(0, uuid_1.v4)()}`,
            version: 1,
            metadata: {
                timestamp: finalResults.start,
                tools: [
                    {
                        vendor: 'RetireJS',
                        name: 'retire.js',
                        version: retire.version,
                    },
                ],
            },
            components: components,
        }, undefined, 2));
        writer.close(callback);
    };
}
function mapLicenses(licenses) {
    if (!licenses)
        return [];
    if (licenses.length == 0)
        return [];
    if (licenses[0] == 'commercial')
        return [{ license: { name: 'Commercial' } }];
    return [{ expression: licenses[0] }];
}
exports.default = {
    configure: configureCycloneDXJSONLogger,
};
