/**
 * The base of every class that owns elements: an element names the methods its events call in
 * `data-handle-event="type:method type:method"`, and the class receives the events through the native
 * `handleEvent` interface.
 */
export class UHandler {
  /**
   * Returns the attribute name used for handling events.
   * @returns {string} The attribute name.
   */
  static handle() {
    return 'data-handle-event';
  }

  /**
   * Registers this instance as the listener of each event type on the element.
   * @param {EventTarget} element The element to listen to.
   * @param {...string} types The event types.
   * @returns {EventTarget} The element.
   */
  listen(element, ...types) {
    for (const type of types) element.addEventListener(type, this);
    return element;
  }

  /**
   * Calls, for each `type:method` of the closest element that carries the attribute, the method whose type is the
   * event's type or empty.
   * @param {Event} event The event.
   */
  handleEvent(event) {
    const element = event.target.closest?.(`[${UHandler.handle()}]`);
    if (element === null || element === undefined) return;
    for (const item of element.getAttribute(UHandler.handle()).split(/\s+/)) {
      const [type, method] = item.split(':');
      if (type !== event.type && type !== '') continue;
      if (typeof this[method] === 'function') this[method](event);
    }
  }
}
