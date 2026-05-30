"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generatePURL = generatePURL;
function encodePURLchars(str) {
    return str.replace(/[^A-Za-z0-9.+/=%-]/g, (match) => '%' + ('0' + match.charCodeAt(0).toString(16).toUpperCase()).slice(-2));
}
function generatePURL(component) {
    if (component.basePurl) {
        const [pType, ...rest] = component.basePurl.split(':');
        const pathElements = rest.join(':').split('/').map(encodePURLchars).join('/');
        return `${pType}:${pathElements}@${encodePURLchars(component.version)}`;
    }
    const compName = component.npmname || component.component;
    return `pkg:npm/${encodePURLchars(compName)}@${encodePURLchars(component.version)}`;
}
