# moonfire-tflite

This is a simple Rust wrapper around the [TensorFlow Lite](https://www.tensorflow.org/lite)
and [edgetpu](https://github.com/google-coral/edgetpu) libraries, created by Scott Lamb &lt;slamb@slamb.org>. It is
primarily used for supporting video analytics in
[Moonfire NVR](https://github.com/scottlamb/moonfire-nvr).

In comparison to the tflite crate, moonfire-tflite has the following advantages:

1. It wraps the [C API](https://github.com/tensorflow/tensorflow/tree/master/tensorflow/lite/c) rather than the C++ API,
   making it simpler and faster to build. It does not require bindgen. (This was the primary reason it was created.)
2. It uses a more recent version of TensorFlow, including
   the [specific commit](https://github.com/google-coral/edgetpu/issues/44#issuecomment-589170013) needed to work with
   the latest edgetpu library. (Updating to a new TensorFlow version is easier due to the simpler API.)
3. It also wraps the `edgetpu` library.

However, moonfire-tflite has the following disadvantages:

- It is less mature, with less usage, no documentation, and no CI.
- It has fewer features, as the C API is not capable of everything the C++ API can do.

## License

Apache-2.0. I would like to dual-license with MIT, but the stock models I'm using for test data are licensed under
Apache. I plan to eventually find or create new test data models and license them.
