var chai = chai || require('chai');
var expect = chai.expect;

describe('WASM', function() {
  it('should not caught exception', (done) => {
    const a = new Promise((resolve, reject) => reject(new Error("test")));

    a.catch(err => { // this handles the `new Error` rejection above
      expect(err.message).to.equal('test'); // this may throw
      done();
    });
  });
});
