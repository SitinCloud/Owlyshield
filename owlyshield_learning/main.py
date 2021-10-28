import datetime
import json
import math

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

ROWS_LEN = 50
COLS_LEN = 21


def preprocess(from_path, length):
    columns = ['app_name', 'gid', 'sum_entropy_weight_r', 'sum_entropy_weight_w', 'extensions_count_r',
               'extensions_count_w',
               'file_ids_c_count', 'file_ids_d_count', 'file_ids_r_count', 'file_ids_rn_count', 'file_ids_w_count',
               'file_ids_u_count',
               'extensions_count_u', 'files_paths_u_count', 'pids_count', 'extensions_count_w_doc',
               'extensions_count_w_archives',
               'extensions_count_w_db', 'extensions_count_w_code', 'extensions_count_w_exe',
               'dir_with_files_c_count', 'dir_with_files_u_count', 'exe_exists']

    df = pd.read_csv(from_path, names=columns, sep=';')

    df['is_ransom'] = df['app_name'].astype(str).apply(lambda x: 'Virus' in x)

    ransom_samples_cnt = df[df['is_ransom']].shape[0]
    legit_samples_cnt = df[df['is_ransom'] == False].shape[0]
    print(f'{ransom_samples_cnt} ransom samples')
    print(f'{legit_samples_cnt} legit samples')

    dataX = []
    dataY = []

    gids = df['gid'].unique()

    for gid in gids:
        x_temp = []
        y_temp = False
        old_appname = ''
        df_gid = df[df['gid'] == gid]
        for (idx, row) in df_gid.iterrows():
            if x_temp != [] and row['app_name'] != old_appname:
                dataX.append(x_temp)
                dataY.append([y_temp])
                x_temp = []

            x_temp.append(row.tolist()[2:-1])
            y_temp = row['is_ransom']
            old_appname = row['app_name']

        dataX.append(x_temp)
        dataY.append([y_temp])

    for i in list(range(len(dataX))):
        dataX[i] = seq_diff(dataX[i])

    x, y = remove_short(dataX, dataY, length, 200)

    return x, y


def remove_short(dataX, dataY, length, seq_count_max):
    new_X = []
    new_Y = []

    max_idx = length * seq_count_max + 1
    idx = 0
    while idx + length < max_idx:
        for x in list(range(len(dataX))):
            if len(dataX[x]) >= idx + length:
                new_X.append(dataX[x][idx:(idx + length)])
                new_Y.append(dataY[x][:length])
        idx += length

    x, y = to_numpy_tensors(new_X, new_Y)
    return x, y


def to_numpy_tensors(x, y):
    x_shape = (len(x), len(x[0]), len(x[0][0]))
    y_shape = (len(y), 1)

    if type(x) is list:
        x = np.array(x)
    if type(y) is list:
        y = np.array(y)

    x = x.reshape(x_shape)
    y = y.reshape(y_shape)

    return x, y


def train_model(x_train, y_train, x_val, y_val):
    model = Sequential()
    model.add(LSTM(units=80, activation='tanh', return_sequences=True, input_shape=(None, 21)))
    model.add(Dropout(0.2))

    model.add(LSTM(units=80, activation='tanh', return_sequences=True))
    model.add(Dropout(0.2))

    model.add(LSTM(units=80, activation='tanh'))
    model.add(Dropout(0.2))

    model.add(Dense(1, activation='sigmoid'))

    model.compile(loss='binary_crossentropy',
                  optimizer='adam',
                  metrics=['accuracy'])

    log_dir = "logs/fit/" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    tensorboard_callback = tf.keras.callbacks.TensorBoard(log_dir=log_dir, histogram_freq=1)

    model.fit(x_train, y_train, batch_size=32, epochs=20, verbose=1,
              validation_data=(x_val, y_val),
              shuffle=False,
              callbacks=[tensorboard_callback])  # for testing

    # model.summary()
    model.save('./models/model_lstm.h5')
    eval_model(model, x_val, y_val)


def eval_model(model, x_val, y_val):
    y_pred = model.predict(x_val, batch_size=64, verbose=1)
    fbool = lambda x: x > 0.5
    y_pred_bool = fbool(y_pred)
    print(classification_report(y_val, y_pred_bool))


def seq_diff(l):
    """
    [ [0, 1], [0, 2], [1, 3] ] -> [ [0, 1], [1, 1] ]
    """
    return l
    # res = []
    # for i in range(len(l) - 1):
    #     value = l[i:i + 2]
    #     l_l = np.array(value[0])
    #     l_r = np.array(value[1])
    #     res.append((l_r - l_l).tolist())
    # return res


def load_data():
    pd.set_option('display.max_columns', None)
    path = r'.\data\learn_data_small_example.csv'

    x, y = preprocess(path, ROWS_LEN)

    x_train, x_val, y_train, y_val = train_test_split(x, y, test_size=0.20, random_state=42, shuffle=True)

    x_train = np.array(x_train)
    x_val = np.array(x_val)
    y_train = np.array(y_train)
    y_val = np.array(y_val)

    scaler = StandardScaler()
    x_train = scaler.fit_transform(x_train.reshape((-1, COLS_LEN))).reshape((-1, ROWS_LEN, COLS_LEN))
    x_val = scaler.transform(x_val.reshape((-1, COLS_LEN))).reshape((-1, ROWS_LEN, COLS_LEN))

    joblib.dump(scaler, './models/scaler_lstm.save')

    return x_train, y_train, x_val, y_val


def convert_model_to_tflite():
    model = keras.models.load_model('./models/model_lstm.h5')
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    tflite_model = converter.convert()
    with open(r'.\models\\model.tflite', 'wb') as f:
        f.write(tflite_model)
    save_scaler_json()


def save_scaler_json():
    scaler = joblib.load('./models/scaler_lstm.save')
    with open('./models/mean.json', 'w') as fp:
        json.dump(scaler.mean_.tolist(), fp)
    with open('./models/std.json', 'w') as fp:
        var = scaler.var_.tolist()
        sigma = list(map(lambda x: math.sqrt(x), var))
        json.dump(sigma, fp)


def main():
    x_train, y_train, x_val, y_val = load_data()
    train_model(x_train, y_train, x_val, y_val)


main()
convert_model_to_tflite()
