rm test/browser/minicrypto.min.js
rm test/browser/crypto.js
rm test/browser/crypto.wasm
cp dist/minicrypto.min.js test/browser
cp src/vendor/wasm/crypto.js test/browser
cp src/vendor/wasm/crypto.wasm test/browser
