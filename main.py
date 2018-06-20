import requests
import json
import pandas as pd
from sklearn.manifold import TSNE
import scipy.spatial.distance as distance
import math



FILES_COUNT = 20
VECTOR_EVENTS_TIME_DELTA_MS = 1000 * 60 * 8
FEATURE_NUMBERS = 39

TIMESTAMP = 'timestamp'
DEVICE_1 = 'deviceVendor'
DEVICE_2 = 'deviceProduct'
SEVERITY = 'severity'
EXTENSIONS = 'extensions'
PROTO = 'proto'
SRC = 'src'
DST = 'dst'
SOURCE_ZONE_URI = 'sourceZoneURI'
DESTINATION_ZONE_URI = 'destinationZoneURI'
SPT = 'spt'
DPT = 'dpt'
BYTES_IN = 'bytesIn'

AGENT = 'agent'
EVENT_NUMBERS = 'eventNumbers'
AGENT_1 = 'CISCO ASA'
AGENT_2 = 'Microsoft Microsoft Windows'
AGENT_3 = 'Unix auditd'
AGENT_4 = 'ArcSight ArcSight'
AGENT_5 = 'CISCO CiscoRouter'
AGENT_6 = 'GIS Ankey SIEM'
AGENT_7 = 'ArcSight ASA'
AGENT_8 = 'Microsoft ArcSight'
SEVERITY_1 = 'Low'
SEVERITY_2 = 'Medium'
SEVERITY_3 = 'Unknown'
SEVERITY_4 = 'High'
SEVERITY_5 = 'Very-High'
PROTO_1 = 'UDP'
PROTO_2 = 'TCP'
PROTO_3 = 'ICMP'
SRC_192 = 'SRC 192.*.*.*'
SRC_NOT_192 = 'SRC not 192.*.*.*'
DST_192 = 'DST 192.*.*.*'
DST_NOT_192 = 'DST not 192.*.*.*'
SOURCE_ZONE_URI_SIEM_ALL = 'sourceZoneURI SIEM ALL'
SOURCE_ZONE_URI_GIS = 'sourceZoneURI Gazinformservice'
SOURCE_ZONE_URI_SIEM_PRIVATE = 'sourceZoneURI SIEM PRIVATE'
SOURCE_ZONE_URI_SIEM_PUBLIC = 'sourceZoneURI SIEM PUBLIC'
SOURCE_ZONE_URI_SIEM_GREY = 'sourceZoneURI SIEM GREY'
DESTINATION_ZONE_URI_SIEM_ALL = 'destinationZoneURI SIEM ALL'
DESTINATION_ZONE_URI_GIS = 'destinationZoneURI Gazinformservice'
DESTINATION_ZONE_URI_SIEM_PRIVATE = 'destinationZoneURI SIEM PRIVATE'
DESTINATION_ZONE_URI_SIEM_PUBLIC = 'destinationZoneURI SIEM PUBLIC'
DESTINATION_ZONE_URI_SIEM_GREY = 'destinationZoneURI SIEM GREY'
SPT_LESS_1024 = 'spt < 1024'
SPT_MORE_1024 = 'spt > 1024'
SPT_WITH_SSH_FTP_TELNET = 'spt with ssh, ftp, telnet'
DPT_LESS_1024 = 'dpt < 1024'
DPT_MORE_1024 = 'dpt > 1024'
DPT_WITH_SSH_FTP_TELNET = 'dpt with ssh, ftp, telnet'
BYTES_IN_SUM = 'sum bytesIn'
BYTES_IN_AVERAGE = 'average bytesIn'
BYTES_IN_MAX = 'max bytesIn'


def download_data():
    url = 'http://10.0.0.9:8090/cefs'

    params = dict(
        size='1000',
        page='3'
    )

    resp = requests.get(url=url, params=params)

    url = resp.json()['_links']['next']['href']

    data = list()
    for i in range(40):
        for j in range(1000):
            resp = requests.get(url)
            data.extend(resp.json()['_embedded']['cefs'])
            print("i = {}, j = {}".format(i, j))
            url = resp.json()['_links']['next']['href']
        with open('rawData/data' + str(i) + '.json', 'w') as outfile:
            json.dump(data, outfile)
            outfile.close()
        data.clear()


def compress_events():
    for i in range(FILES_COUNT):
        print('try to read')
        with open('rawData/data' + str(i) + '.json') as json_file:
            events = json.load(json_file)

        print('try to compress')
        compressed_events = list()

        for item in events:
            compressed_item = dict()
            compressed_item[TIMESTAMP] = item[TIMESTAMP]
            compressed_item[AGENT] = item[DEVICE_1] + ' ' + item[DEVICE_2]
            compressed_item[SEVERITY] = item[SEVERITY]
            if PROTO in item[EXTENSIONS]:
                compressed_item[PROTO] = item[EXTENSIONS][PROTO]
            if SRC in item[EXTENSIONS]:
                compressed_item[SRC] = item[EXTENSIONS][SRC]
            if DST in item[EXTENSIONS]:
                compressed_item[DST] = item[EXTENSIONS][DST]
            if SOURCE_ZONE_URI in item[EXTENSIONS]:
                compressed_item[SOURCE_ZONE_URI] = item[EXTENSIONS][SOURCE_ZONE_URI]
            if DESTINATION_ZONE_URI in item[EXTENSIONS]:
                compressed_item[DESTINATION_ZONE_URI] = item[EXTENSIONS][DESTINATION_ZONE_URI]
            if SPT in item[EXTENSIONS]:
                compressed_item[SPT] = item[EXTENSIONS][SPT]
            if DPT in item[EXTENSIONS]:
                compressed_item[DPT] = item[EXTENSIONS][DPT]
            if BYTES_IN in item[EXTENSIONS]:
                compressed_item[BYTES_IN] = item[EXTENSIONS][BYTES_IN]

            compressed_events.append(compressed_item)

        print('try to save')
        with open('compressedData/data' + str(i) + '.json', 'w') as outfile:
            json.dump(compressed_events, outfile)
            outfile.close()

        compressed_events.clear()
        events.clear()


def events_to_vectors():
    events = list()

    vectors = list()


    events_for_vector = list()

    vector = dict()

    for i in range(1, FILES_COUNT):
        events.clear()
        with open('mongoCompressedData/data' + str(i) + '.json') as json_file:
            events.extend(json.load(json_file))
            print(i)

        if len(events_for_vector) == 0 and len(vectors) == 0:
            startTime = events[0][TIMESTAMP]


        for event in events:
            if event[TIMESTAMP] - startTime < VECTOR_EVENTS_TIME_DELTA_MS:
                events_for_vector.append(event)
            else:
                print(startTime)

                vector[EVENT_NUMBERS] = len(events_for_vector)

                agent_1 = 0
                agent_2 = 0
                agent_3 = 0
                agent_4 = 0
                agent_5 = 0
                agent_6 = 0
                agent_7 = 0
                agent_8 = 0

                severity_1 = 0
                severity_2 = 0
                severity_3 = 0
                severity_4 = 0
                severity_5 = 0

                proto_1 = 0
                proto_2 = 0
                proto_3 = 0

                src_192 = 0
                src_not_192 = 0
                dst_192 = 0
                dst_not_192 = 0

                source_zone_uri_siem_all = 0
                source_zone_uri_gis = 0
                source_zone_uri_siem_private = 0
                source_zone_uri_siem_public = 0
                source_zone_uri_siem_grey = 0

                destination_zone_uri_siem_all = 0
                destination_zone_uri_gis = 0
                destination_zone_uri_siem_private = 0
                destination_zone_uri_siem_public = 0
                destination_zone_uri_siem_grey = 0

                spt_less_1024 = 0
                spt_more_1024 = 0
                spt_with_ssh_ftp_telnet = 0

                dpt_less_1024 = 0
                dpt_more_1024 = 0
                dpt_with_ssh_ftp_telnet = 0

                bytes_in_sum = 0
                bytes_in_max = 0
                number_of_bytes_in = 0

                for event in events_for_vector:
                    if event[AGENT] == AGENT_1:
                        agent_1 += 1
                    elif event[AGENT] == AGENT_2:
                        agent_2 += 1
                    elif event[AGENT] == AGENT_3:
                        agent_3 += 1
                    elif event[AGENT] == AGENT_4:
                        agent_4 += 1
                    elif event[AGENT] == AGENT_5:
                        agent_5 += 1
                    elif event[AGENT] == AGENT_6:
                        agent_6 += 1
                    elif event[AGENT] == AGENT_7:
                        agent_7 += 1
                    elif event[AGENT] == AGENT_8:
                        agent_8 += 1

                    if event[SEVERITY] == SEVERITY_1:
                        severity_1 += 1
                    elif event[SEVERITY] == SEVERITY_2:
                        severity_2 += 1
                    elif event[SEVERITY] == SEVERITY_3:
                        severity_3 += 1
                    elif event[SEVERITY] == SEVERITY_4:
                        severity_4 += 1
                    elif event[SEVERITY] == SEVERITY_5:
                        severity_5 += 1

                    if PROTO in event:
                        if event[PROTO] == PROTO_1:
                            proto_1 += 1
                        elif event[PROTO] == PROTO_2:
                            proto_2 += 1
                        elif event[PROTO] == PROTO_3:
                            proto_3 += 1


                    if SRC in event:
                        splitted = event[SRC].split('.')
                        if splitted[0] == '192':
                            src_192 += 1
                        else:
                            src_not_192 += 1
                    if DST in event:
                        splitted = event[DST].split('.')
                        if splitted[0] == '192':
                            dst_192 += 1
                        else:
                            dst_not_192 += 1
                    if SOURCE_ZONE_URI in event:
                        splitted = event[SOURCE_ZONE_URI].split('/')
                        if splitted[2] == 'Системные Ankey SIEM':
                            source_zone_uri_siem_all += 1
                        else:
                            source_zone_uri_gis += 1
                        if 'частных' in splitted[3]:
                            source_zone_uri_siem_private += 1
                        elif 'общедоступных' in splitted[3]:
                            source_zone_uri_siem_public += 1
                        elif 'серых' in splitted[3]:
                            source_zone_uri_siem_grey += 1
                    if DESTINATION_ZONE_URI in event:
                        splitted = event[DESTINATION_ZONE_URI].split('/')
                        if splitted[2] == 'Системные Ankey SIEM':
                            destination_zone_uri_siem_all += 1
                        else:
                            destination_zone_uri_gis += 1
                        if 'частных' in splitted[3]:
                            destination_zone_uri_siem_private += 1
                        elif 'общедоступных' in splitted[3]:
                            destination_zone_uri_siem_public += 1
                        elif 'серых' in splitted[3]:
                            destination_zone_uri_siem_grey += 1
                    if SPT in event:
                        port = int(event[SPT])
                        if port < 1024:
                            spt_less_1024 += 1
                        else:
                            spt_more_1024 += 1
                        if port > 19 and port < 24:
                            spt_with_ssh_ftp_telnet += 1
                    if DPT in event:
                        try:
                            port = int(event[DPT])
                        except ValueError:
                            print("error val " + event[DPT])
                        if port < 1024:
                            dpt_less_1024 += 1
                        else:
                            dpt_more_1024 += 1
                        if port > 19 and port < 24:
                            dpt_with_ssh_ftp_telnet += 1
                    if BYTES_IN in event:
                        number_of_bytes_in += 1
                        bytes = int(event[BYTES_IN])
                        bytes_in_sum += bytes
                        if bytes > bytes_in_max:
                            bytes_in_max = bytes

                vector[AGENT_1] = agent_1
                vector[AGENT_2] = agent_2
                vector[AGENT_3] = agent_3
                vector[AGENT_4] = agent_4
                vector[AGENT_5] = agent_5
                vector[AGENT_6] = agent_6
                vector[AGENT_7] = agent_7
                # vector[AGENT_8] = agent_8

                vector[SEVERITY_1] = severity_1
                vector[SEVERITY_2] = severity_2
                vector[SEVERITY_3] = severity_3
                vector[SEVERITY_4] = severity_4
                vector[SEVERITY_5] = severity_5

                vector[PROTO_1] = proto_1
                vector[PROTO_2] = proto_2
                vector[PROTO_3] = proto_3

                vector[SRC_192] = src_192
                vector[SRC_NOT_192] = src_not_192
                vector[DST_192] = dst_192
                vector[DST_NOT_192] = dst_not_192

                vector[SOURCE_ZONE_URI_SIEM_ALL] = source_zone_uri_siem_all
                vector[SOURCE_ZONE_URI_GIS] = source_zone_uri_gis
                vector[SOURCE_ZONE_URI_SIEM_PRIVATE] = source_zone_uri_siem_private
                vector[SOURCE_ZONE_URI_SIEM_PUBLIC] = source_zone_uri_siem_public
                vector[SOURCE_ZONE_URI_SIEM_GREY] = source_zone_uri_siem_grey

                vector[DESTINATION_ZONE_URI_SIEM_ALL] = destination_zone_uri_siem_all
                vector[DESTINATION_ZONE_URI_GIS] = destination_zone_uri_gis
                vector[DESTINATION_ZONE_URI_SIEM_PRIVATE] = destination_zone_uri_siem_private
                vector[DESTINATION_ZONE_URI_SIEM_PUBLIC] = destination_zone_uri_siem_public
                vector[DESTINATION_ZONE_URI_SIEM_GREY] = destination_zone_uri_siem_grey

                vector[SPT_LESS_1024] = spt_less_1024
                vector[SPT_MORE_1024] = spt_more_1024
                vector[SPT_WITH_SSH_FTP_TELNET] = spt_with_ssh_ftp_telnet

                vector[DPT_LESS_1024] = dpt_less_1024
                vector[DPT_MORE_1024] = dpt_more_1024
                vector[DPT_WITH_SSH_FTP_TELNET] = dpt_with_ssh_ftp_telnet

                vector[BYTES_IN_SUM] = bytes_in_sum
                if number_of_bytes_in == 0:
                    vector[BYTES_IN_AVERAGE] = 0
                else:
                    vector[BYTES_IN_AVERAGE] = round(bytes_in_sum / number_of_bytes_in)
                vector[BYTES_IN_MAX] = bytes_in_max

                vectors.append(vector)
                startTime = event[TIMESTAMP]
                vector = dict()
                events_for_vector.clear()
    with open('mongoVectors/vectors' + str(int(VECTOR_EVENTS_TIME_DELTA_MS / 60 / 1000)) + '.json', 'w') as outfile:
        json.dump(vectors, outfile)
        outfile.close()


def get_array():
    vectors = list()
    with open('/home/ihb/PycharmProjects/testProject/mongoVectors/vectors1.json') as json_file:
        vectors.extend(json.load(json_file))
    X_all = [None] * len(vectors)
    for i in range(len(vectors)):
        vector = vectors[i]
        keys = list(vector.keys())
        x = [None] * FEATURE_NUMBERS
        for j in range(FEATURE_NUMBERS):
            x[j] = vector[keys[j]]
            if x[j] == 0:
                x[j] = 1
        X_all[i] = x
    return X_all

class MahalanobisCallable:

    def __init__(self, vi, metric = None):
        self.vi = vi
        self.metric = metric

    def __call__(self, x1, x2):
        res = distance.mahalanobis(x1, x2, self.vi)
        if math.isnan(res):
            res = 0
            print('nan!')
        return res


import numpy as np
from scipy import stats
import matplotlib.pyplot as plt
import matplotlib.font_manager

from sklearn import svm
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

print(__doc__)


X = get_array()

X_df = pd.DataFrame(X)
covmx = X_df.cov()
invcovmx = np.linalg.inv(covmx)
mahalanobis_callable = MahalanobisCallable(invcovmx)

n_samples = len(X)
outliers_fraction = 0.25

plot_X = 10
plot_Y = 10

rng = np.random.RandomState(42)

tsne = TSNE(random_state=rng, metric=mahalanobis_callable)
X = tsne.fit_transform(X)

xx, yy = np.meshgrid(np.linspace(-plot_X, plot_X, 100), np.linspace(-plot_Y, plot_Y, 100))

classifiers = {
    "Isolation Forest": IsolationForest(max_samples=n_samples,
                                        contamination=outliers_fraction,
                                        random_state=rng),
    "Local Outlier Factor": LocalOutlierFactor(
        n_neighbors=round(math.sqrt(len(X))),
        contamination=outliers_fraction)}

plt.figure(figsize=(10 * len(classifiers), 10))
for i, (clf_name, clf) in enumerate(classifiers.items()):
    if clf_name == "Local Outlier Factor":
        y_pred = clf.fit_predict(X)
        scores_pred = clf.negative_outlier_factor_
    else:
        clf.fit(X)
        scores_pred = clf.decision_function(X)
        y_pred = clf.predict(X)
    threshold = stats.scoreatpercentile(scores_pred,
                                        100 * outliers_fraction)
    if clf_name == "Local Outlier Factor":
        Z = clf._decision_function(np.c_[xx.ravel(), yy.ravel()])
    else:
        Z = clf.decision_function(np.c_[xx.ravel(), yy.ravel()])
    Z = Z.reshape(xx.shape)
    subplot = plt.subplot(1, len(classifiers), i + 1)
    subplot.contourf(xx, yy, Z, levels=np.linspace(Z.min(), threshold, 7),
                     cmap=plt.cm.Blues_r)
    a = subplot.contour(xx, yy, Z, levels=[threshold],
                        linewidths=2, colors='red')
    subplot.contourf(xx, yy, Z, levels=[threshold, Z.max()],
                     colors='orange')
    norm = list()
    for index in range(len(X)):
        if y_pred[index] == 1:
            norm.append(X[index])
    norm = np.array(norm)

    outline = list()
    for index in range(len(X)):
        if y_pred[index] == -1:
            outline.append(X[index])
    outline = np.array(outline)

    b = subplot.scatter(norm[:, 0], norm[:, 1], c='white',
                        s=20, edgecolor='k')
    c = subplot.scatter(outline[:, 0], outline[:, 1], c='black',
                        s=20, edgecolor='k')
    subplot.axis('tight')
    subplot.legend(
        [a.collections[0], b, c],
        ['learned decision function', 'inliers', 'outliers'],
        prop=matplotlib.font_manager.FontProperties(size=20),
        loc='lower right')
    subplot.set_xlabel("%d. %s" % (i + 1, clf_name))
    subplot.set_xlim((-plot_X, plot_X))
    subplot.set_ylim((-plot_Y, plot_Y))

plt.suptitle("Outlier detection")
plt.show()