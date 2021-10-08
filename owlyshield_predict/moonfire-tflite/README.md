# moonfire-tflite

This is a simple Rust wrapper around the [TensorFlow
Lite](https://www.tensorflow.org/lite) and
[edgetpu](https://github.com/google-coral/edgetpu) libraries, written by
Scott Lamb &lt;slamb@slamb.org>. It's primarily made to support video
analytics in [Moonfire NVR](https://github.com/scottlamb/moonfire-nvr).

As compared to the [tflite crate](https://crates.io/crates/tflite), advantages:

*   Because it wraps the [C
    API](https://github.com/tensorflow/tensorflow/tree/master/tensorflow/lite/c)
    rather than the C++ API, it's simpler and quicker to build. It doesn't need
    bindgen. (This is the primary reason I wrote my own.)
*   It runs with a more modern version of TensorFlow, including the [specific
    commit](https://github.com/google-coral/edgetpu/issues/44#issuecomment-589170013)
    needed to work with the latest `edgetpu` library. (Adjusting to new
    TensorFlow version is much easier because of the simpler API.)
*   It wraps the `edgetpu` library as well.

Disadvantages:

*   It's much less mature: less usage, no documentation, no CI.
*   It's less feature-rich; the C API can't do everything the C++ API can.

## License

Apache-2.0. I'd like to dual-license with MIT, but the stock models I'm using
for test data are Apache-licensed. Eventually I will find or make new test data
models and relicense.
