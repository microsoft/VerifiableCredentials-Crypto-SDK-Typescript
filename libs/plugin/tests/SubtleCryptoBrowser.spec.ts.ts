import { SubtleCryptoBrowser } from '../lib';

describe('SubtleCryptoBrowser', () => {
    it('should create a SubtleCryptoBrowser', () => {

        const subtleBrowser = new SubtleCryptoBrowser();
        expect(() => subtleBrowser.getSubtleCrypto()).toThrowError('window is not defined. Must be defined in browser.');
    });
});