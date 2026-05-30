"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.evaluateLicense = evaluateLicense;
const retire_1 = require("./retire");
function evaluateLicense(licenses, version) {
    const parsedLicenses = licenses.map((license) => {
        let splitIndex = license.indexOf(' ');
        let licenseName = license.slice(0, splitIndex);
        if (license.startsWith('(')) {
            splitIndex = license.slice(1).indexOf(')') + 1;
            licenseName = license.slice(1, splitIndex);
        }
        //console.log(license, '|', splitIndex, '|', licenseName, '|', license.slice(splitIndex + 1));
        const ranges = license
            .slice(splitIndex + 1)
            .trim()
            .split(';')
            .map((x) => x.trim())
            .map((range) => {
            const [from, to] = range.split(' ').map((v) => v.trim());
            if (!from.startsWith('>='))
                throw new Error("Invalid license range: 'from' must start with '>=': " + range + '[' + from + ']' + '[' + to + ']');
            if (to && !to.startsWith('<'))
                throw new Error("Invalid license range: 'to' must start with '<': " + range);
            if (to && to.startsWith('<='))
                throw new Error("Invalid license range: 'to' must start with '<': " + range);
            return { from: from.replace('>=', ''), to: to ? to.replace('<', '') : undefined };
        });
        return { licenseName, ranges };
    });
    return parsedLicenses
        .filter((parsedLicense) => {
        return parsedLicense.ranges.some((range) => {
            if (range.from && range.to) {
                return (0, retire_1.isAtOrAbove)(version, range.from) && (0, retire_1.isAtOrAbove)(range.to, version);
            }
            if (range.from) {
                return (0, retire_1.isAtOrAbove)(version, range.from);
            }
            return false;
        });
    })
        .map((parsedLicense) => parsedLicense.licenseName);
}
