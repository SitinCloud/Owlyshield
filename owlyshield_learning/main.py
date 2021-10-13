import numpy as np
import tensorflow as tf
import pandas as pd
import datetime
from tensorflow.python.keras import Sequential
from tensorflow.python.keras.layers import Dense, BatchNormalization, Dropout
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from tensorflow import keras

ROWS_LEN = 10
COLS_LEN = 21

def load_inputs(df, vectors_size, is_test_set):
    df_tmp = df[df['test_set'] == is_test_set]
    X = []
    Y = []
    sample_ids = df_tmp['sample_id'].unique()
    for sample_id in sample_ids:
        df_sample_id = df_tmp[df_tmp['sample_id'] == sample_id]

        last_vector = 0
        X_temp = []
        for (idx, row) in df_sample_id.iterrows():
            vector = row['vector']
            if last_vector == 0 and vector > 1:
                continue
            if vector == last_vector:
                continue
            if vector < last_vector:
                if last_vector == vectors_size:
                    X.append(X_temp)
                    if len(X_temp) != 10:
                        print("Critical - This should not happen")
                        quit()
                    Y.append(row['is_ransom'])
                    last_vector = 0
                    X_temp = []
                elif last_vector < vectors_size:
                    X_temp = []
            X_temp.append(row.tolist()[3:24])
            last_vector = vector

    return X,Y

def train_model(x_train, y_train, x_val, y_val):
    model = Sequential()
    model.add(Dense(80, activation='relu', input_shape=(ROWS_LEN * COLS_LEN,)))
    model.add(BatchNormalization())
    model.add(Dense(80, activation='relu'))
    model.add(BatchNormalization())
    model.add(Dense(80, activation='relu'))
    model.add(BatchNormalization())
    model.add(Dropout(0.2))
    model.add(Dense(1, activation='sigmoid'))

    model.compile(loss='binary_crossentropy',
                  optimizer='adam',
                  metrics=['accuracy'])

    model.summary()
    log_dir = "logs/fit/" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    tensorboard_callback = tf.keras.callbacks.TensorBoard(log_dir=log_dir, histogram_freq=1)

    model.fit(x_train, y_train, batch_size=32, epochs=50, verbose=1,
              validation_data=(x_val, y_val),
              shuffle=False,
              callbacks=[tensorboard_callback]) # for testing

    model.save('./models/model.h5')

    eval_model(model, x_val, y_val)

def eval_model(model, x_val, y_val):
    y_pred = model.predict(x_val, batch_size=64, verbose=1)
    fbool = lambda x: x > 0.5
    y_pred_bool = fbool(y_pred)
    print(classification_report(y_val, y_pred_bool))

def load_data() :
    pd.set_option('display.max_columns', None)
    sep = ","
    path = r".\data\learn_data_small_example.csv"
    df = pd.read_csv(path, sep=sep)

    x, y = load_inputs(df, 10, False)

    train_ransomwares = len([r for r in y if r])

    x_train, x_val, y_train, y_val = train_test_split(x, y, test_size=0.25, random_state=42, shuffle=True)
    xx_train = np.array(x_train)
    xx_val = np.array(x_val)
    xx_train = xx_train.reshape(xx_train.shape[0], ROWS_LEN * COLS_LEN)
    xx_val = xx_val.reshape(xx_val.shape[0], ROWS_LEN * COLS_LEN)
    yy_train = np.array(y_train)
    yy_val = np.array(y_val)

    return (xx_train, yy_train, xx_val, yy_val)

def convert_model_to_tflite(model):
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    tflite_model = converter.convert()
    with open(r'.\models\\converted.tflite', 'wb') as f:
        f.write(tflite_model)

def Normalize(data, mean_data =None, std_data =None):
    if not mean_data:
        mean_data = np.mean(data)
    if not std_data:
        std_data = np.std(data)
    norm_data = (data-mean_data)/std_data
    return norm_data, mean_data, std_data

def main():
    x_train, y_train, x_val, y_val = load_data()
    #x_train, mean_data, std_data = Normalize(x_train)
    #x_val, _, _ = Normalize(x_val, mean_data, std_data)
    train_model(x_train, y_train, x_val, y_val)
    model = keras.models.load_model('./models/model.h5')
    #eval_model(model, x_val, y_val)
    convert_model_to_tflite(model)

if __name__ == '__main__':
    main()

