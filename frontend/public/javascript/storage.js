/**
 * The one preference the page keeps in the browser: the terminal's font size. A storage that throws, holds no
 * entry or holds something else reads as the default, and a write that fails leaves the page working.
 */
export class UStorage {
  static key = 'uwsb.fontsize';
  static min = 8;
  static max = 32;

  #storage;

  /**
   * Constructs a new UStorage instance.
   * @param {function(): Storage} storage Returns the storage; reaching `localStorage` throws where the browser
   *   blocks it, so the call sits inside each read and write.
   */
  constructor(storage) {
    this.#storage = storage;
  }

  /**
   * Reads the stored font size.
   * @param {number} fallback The size of a missing, unreadable or out-of-range entry.
   * @returns {number} The font size.
   */
  fontSize(fallback) {
    try {
      const text = this.#storage().getItem(UStorage.key);
      if (!/^[1-9][0-9]?$/.test(text)) return fallback;
      const size = Number(text);
      return UStorage.fits(size) ? size : fallback;
    } catch {
      return fallback;
    }
  }

  /**
   * Stores the font size.
   * @param {number} size The font size, from 8 to 32.
   */
  setFontSize(size) {
    try {
      this.#storage().setItem(UStorage.key, String(size));
    } catch {
      // A full or blocked storage keeps the size for this tab only.
    }
  }

  /**
   * Tells whether a font size lies in the range the page accepts.
   * @param {number} size The font size.
   * @returns {boolean} True from 8 to 32.
   */
  static fits(size) {
    return Number.isInteger(size) && size >= UStorage.min && size <= UStorage.max;
  }
}
