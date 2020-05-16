var Module = Module || require('./vendor/wasm/wrapper');

exports.WASMEngineMixin = {
  async create() {
    const self = this;
    await Module.isReady;

    return new this(...arguments);
  }
};
