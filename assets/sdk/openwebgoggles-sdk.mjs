/**
 * OpenWebGoggles SDK — ESM entry point
 *
 * Re-exports the UMD build as an ES module for bundlers and native ESM environments.
 *
 * Usage (bundler / Node.js ESM):
 *   import OpenWebGoggles from 'openwebgoggles';
 *
 * Usage (browser ESM via CDN / importmap):
 *   import OpenWebGoggles from '/sdk/openwebgoggles-sdk.mjs';
 *
 * The SDK still requires a browser environment (window, WebSocket, SubtleCrypto)
 * when actually connecting. Importing the module in Node.js for type-checking
 * or static analysis is fine — connect() must be called in a browser context.
 */

// The UMD build detects module.exports and assigns there in a CommonJS context.
// We import it here and re-export as the default ES module export.
import _sdk from "./openwebgoggles-sdk.js";

export default _sdk;
