import datetime
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow import keras
from tensorflow.python.keras import Sequential
from tensorflow.python.keras.layers import Dense, Dropout, LSTM

ROWS_LEN = 20
COLS_LEN = 21

def load_inputs(df, is_test_set, min_set_len):
    # df_tmp = df[df['test_set'] == is_test_set]
    df_tmp = df
    X = []
    Y = []
    sample_ids = df_tmp['sample_id'].unique()
    for sample_id in sample_ids:
        df_sample_id = df_tmp[df_tmp['sample_id'] == sample_id]
        sample_id_len = len(df_sample_id)
        if sample_id_len < min_set_len:
            continue
        X_temp = []
        idx_zero = 0
        for (idx, row) in df_sample_id.iterrows():
            if (idx_zero + min_set_len) >= sample_id_len:
                break
            if len(X_temp) == min_set_len:
                X.append(X_temp)
                Y.append(row['is_ransom'])
                X_temp = []
            X_temp.append(row.tolist()[3:24])
            idx_zero += 1

    return X, Y


def train_model(x_train, y_train, x_val, y_val):
    model = Sequential()
    model.add((LSTM(units=80, return_sequences=True, input_shape=(x_train.shape[1], COLS_LEN))))
    model.add(Dropout(0.2))

    model.add((LSTM(units=80, return_sequences=True)))
    model.add(Dropout(0.2))

    # model.add((LSTM(units=80, return_sequences=True)))
    # model.add(Dropout(0.2))

    model.add(LSTM(units=50))
    model.add(Dropout(0.2))

    model.add(Dense(1, activation='sigmoid'))

    model.compile(loss='binary_crossentropy',
                  optimizer='adam',
                  metrics=['accuracy'])

    model.summary()
    log_dir = "logs/fit/" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    tensorboard_callback = tf.keras.callbacks.TensorBoard(log_dir=log_dir, histogram_freq=1)

    model.fit(x_train, y_train, batch_size=32, epochs=25, verbose=1,
              validation_data=(x_val, y_val),
              shuffle=False,
              callbacks=[tensorboard_callback])  # for testing

    model.save('./models/model_lstm.h5')
    eval_model(model, x_val, y_val)


def eval_model(model, x_val, y_val):
    y_pred = model.predict(x_val, batch_size=64, verbose=1)
    fbool = lambda x: x > 0.5
    y_pred_bool = fbool(y_pred)
    print(classification_report(y_val, y_pred_bool))


def load_data():
    pd.set_option('display.max_columns', None)
    sep = ","
    path = r".\data\learn_data_small_example.csv"
    # path = r'D:\Azure\Learn270721\learn_all_f.csv';
    df = pd.read_csv(path, sep=sep)
    # df = pd.read_csv(path, sep=sep, nrows=10000)

    x, y = load_inputs(df, False, 10)

    x_train, x_val, y_train, y_val = train_test_split(x, y, test_size=0.25, random_state=42, shuffle=True)

    xx_train = np.array(x_train)
    xx_val = np.array(x_val)
    yy_train = np.array(y_train)
    yy_val = np.array(y_val)

    scaler = StandardScaler()
    xx_train = scaler.fit_transform(xx_train.reshape(-1, xx_train.shape[-1])).reshape(xx_train.shape)
    xx_val = scaler.transform(xx_val.reshape(-1, xx_val.shape[-1])).reshape(xx_val.shape)
    joblib.dump(scaler, './models/scaler_lstm.save')

    return (xx_train, yy_train, xx_val, yy_val)


def convert_model_to_tflite(model):
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    tflite_model = converter.convert()
    with open(r'.\models\\converted.tflite', 'wb') as f:
        f.write(tflite_model)


def Normalize(data, mean_data=None, std_data=None):
    if not mean_data:
        mean_data = np.mean(data)
    if not std_data:
        std_data = np.std(data)
    norm_data = (data - mean_data) / std_data
    return norm_data, mean_data, std_data


def main_lstm():
    x_train, y_train, x_val, y_val = load_data()
    train_model(x_train, y_train, x_val, y_val)
    model = keras.models.load_model('./models/model_lstm.h5')
    scaler = joblib.load('./models/scaler_lstm.save')
    # eval_model(model, x_val, y_val)
    # convert_model_to_tflite(model)


main_lstm()
