"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deepScan = deepScan;
const astronomical_1 = require("astronomical");
const retire_1 = require("./retire");
function deepScan(content, repo) {
    const astQueries = {};
    const backMap = {};
    Object.entries(repo).forEach(([name, data]) => {
        data.extractors.ast?.forEach((query, i) => {
            astQueries[`${name}_${i}`] = query;
            backMap[`${name}_${i}`] = name;
        });
    });
    const results = (0, astronomical_1.multiQuery)(content, astQueries);
    const detected = [];
    Object.entries(results).forEach(([key, value]) => {
        value.forEach((match) => {
            const component = backMap[key];
            if (typeof match !== 'string')
                return;
            detected.push({
                version: match,
                component: component,
                npmname: repo[component].npmname,
                basePurl: repo[component].basePurl,
                detection: 'ast',
            });
        });
    });
    return detected.reduce((acc, cur) => {
        if (acc.some((c) => c.component === cur.component && c.version === cur.version))
            return acc;
        return acc.concat((0, retire_1.check)(cur.component, cur.version, repo));
    }, []);
}
