const fs = require('fs');
const gentlyCopy = require('gently-copy');

const distPaths = ['build', 'public', 'dist'];

function copyWASM(destination) {
  gentlyCopy(['./src/vendor/wasm/crypto.wasm'], destination);
}

distPaths.map(path => {
  const relative = './' + path;
  if (fs.existsSync(relative)) {
    if (path === "public") {
      const jsPath = relative + '/js';

      if (fs.existsSync(jsPath)) copyWASM(jsPath);
      else copyWASM(relative);
    }
    else copyWASM(relative);
  }
});
