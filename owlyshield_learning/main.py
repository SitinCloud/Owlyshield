import datetime
import json
import math

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from common import columns
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow import keras
from tensorflow.python.keras import Sequential
from tensorflow.python.keras.layers import Dense, Dropout, LSTM, Masking, Bidirectional
from tensorflow.python.keras.optimizer_v2.adam import Adam
from tensorflow.python.keras.optimizer_v2.rmsprop import RMSProp

ROWS_LEN = 100
COLS_LEN = 25
EPOCHS = 5
SEQ_LEN = 10

import os
# os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

def preprocess(from_path, length):
    df = pd.read_csv(from_path, names=columns, sep=';') #, nrows=10000)

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

    dataX_train, dataX_val, dataY_train, dataY_val = train_test_split(dataX, dataY, test_size=0.99, random_state=42, shuffle=True)
    x_train, y_train = remove_short_tbptt_padding(dataX_train, dataY_train, ROWS_LEN, SEQ_LEN)
    x_val, y_val = remove_short_tbptt_padding(dataX_val, dataY_val, ROWS_LEN, SEQ_LEN)

    return x_train, x_val, y_train, y_val


def remove_short_padding(dataX, dataY):
    new_X = []
    new_Y = []

    special = []
    for i in range(COLS_LEN):
        special.append(-10.0)

    for x in list(range(len(dataX))):
        dataX_x_len = len(dataX[x])
        if len(dataX[x]) > ROWS_LEN:
            #new_X.append(dataX[x])
            new_X.append(dataX[x][:ROWS_LEN])
            new_Y.append(dataY[x])
        elif dataX_x_len > 20:
            temp_x = []
            temp_x.append(dataX[x][:dataX_x_len])
            for i in range(ROWS_LEN-dataX_x_len):
                temp_x[0].append(special)
            new_X.append(temp_x[0])
            new_Y.append(dataY[x])

    x, y = to_numpy_tensors(new_X, new_Y)
    return x, y



def remove_short_tbptt(dataX, dataY, length, seq_count_max):
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


def remove_short_tbptt_padding(dataX, dataY, length, seq_count_max):
    new_X = []
    new_Y = []

    remove_malfunctioning_viruses(dataX, dataY)

    special = []
    for i in range(COLS_LEN):
        special.append(-10.0)

    for x in list(range(len(dataX))):
        dataX_x_len = len(dataX[x])
        if 50 < len(dataX[x]) < ROWS_LEN:
            temp_x = []
            temp_x.append(dataX[x][:dataX_x_len])
            for i in range(ROWS_LEN - dataX_x_len):
                temp_x[0].append(special)
            new_X.append(temp_x[0])
            new_Y.append(dataY[x])

    max_idx = length * seq_count_max
    idx = 0
    while idx + length < max_idx + 1:
        for xi in range(len(dataX)):
            if len(dataX[xi]) >= idx + length:
                new_X.append(dataX[xi][idx:(idx + length)])
                new_Y.append(dataY[xi])

        idx += length

    x, y = to_numpy_tensors(new_X, new_Y)
    return x, y

def remove_malfunctioning_viruses(x, y):
    def inner(x, y):
        index_to_pop = []
        for i in list(range(len(x))):
            if y[i][0]:
                if len(x[i]) < 1000:
                    index_to_pop.append(i)

        span = 0
        for i in index_to_pop:
            x.pop(i-span)
            y.pop(i-span)
            span+=1

    inner(x, y)

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

    model.add(Masking(mask_value=-10.0, input_shape=(None, COLS_LEN)))
    model.add(Bidirectional(LSTM(units=100, activation='tanh', return_sequences=True)))
    model.add(Dropout(0.2))
    model.add(Bidirectional(LSTM(units=100, activation='tanh', return_sequences=True)))
    model.add(Dropout(0.2))
    model.add(Bidirectional(LSTM(units=100, activation='tanh')))
    model.add(Dropout(0.2))

    model.add(Dense(1, activation='sigmoid'))

    model.compile(loss='binary_crossentropy',
                  #optimizer=Adam(learning_rate=0.001),
                  # optimizer=RMSProp(learning_rate=0.0001, momentum=0.1),
                  optimizer=RMSProp(),
                  metrics=['accuracy'])

    log_dir = "logs/fit/" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    tensorboard_callback = tf.keras.callbacks.TensorBoard(log_dir=log_dir, histogram_freq=1)

    model.fit(x_train, y_train, batch_size=256, epochs=EPOCHS, verbose=1,
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
    path = r'.\data\learn.csv'

    x_train, x_val, y_train, y_val = preprocess(path, ROWS_LEN)

    # x_train, x_val, y_train, y_val = train_test_split(x, y, test_size=0.1, random_state=42, shuffle=True)

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


# main()
# convert_model_to_tflite()


model = keras.models.load_model('./models/model_lstm.h5')
scaler = joblib.load('./models/scaler_lstm.save')
x_train, y_train, x_val, y_val = load_data()
eval_model(model, x_val, y_val)
