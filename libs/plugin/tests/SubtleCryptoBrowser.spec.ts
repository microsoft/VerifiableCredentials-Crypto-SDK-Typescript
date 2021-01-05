import { SubtleCryptoBrowser, Subtle } from '../lib';

describe('SubtleCryptoBrowser', () => {
    it('should create a SubtleCryptoBrowser', () => {

        const subtleBrowser = new SubtleCryptoBrowser();
        expect(() => subtleBrowser.getSubtleCrypto()).toThrowError('window is not defined. Must be defined in browser.');
        expect(() => SubtleCryptoBrowser.getSubtleCrypto()).toThrowError('window is not defined. Must be defined in browser.');
    });
    it('should test algorithmTransform', () => {
        let subtle = new SubtleCryptoBrowser();
        let alg: any = {test: 'name'};
        expect(subtle.algorithmTransform(alg)).toEqual(alg);
        alg = {foo: 'fighters'};
        expect(subtle.algorithmTransform(alg)).toEqual(alg);
    });
    it('should test keyImportTransform', () => {
        let subtle: any = new SubtleCryptoBrowser();
        let jwk: any = {test: 'name'};
        expect(subtle.keyImportTransform(jwk)).toEqual(jwk);
        jwk = {foo: 'fighters'};
        expect(subtle.keyImportTransform(jwk)).toEqual(jwk);
    });
    it('should test keyExportTransform', () => {
        let subtle: any = new SubtleCryptoBrowser();
        let jwk: any = {test: 'name'};
        expect(subtle.keyExportTransform(jwk)).toEqual(jwk);
        jwk = {foo: 'fighters'};
        expect(subtle.keyExportTransform(jwk)).toEqual(jwk);
    });
});