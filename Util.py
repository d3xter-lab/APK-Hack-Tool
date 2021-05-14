import os
import subprocess

def startAdbServer():
    p = subprocess.Popen('adb start-server', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = p.communicate()

def getAppInformation(aapt, app):
    appInfo = []
    appPerm = []

    cmd = '"' + aapt + '" dump badging "' + app + '"'
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = p.communicate()
    temp = out.decode('utf-8').split('\n')
    info1 = temp[0].split('\u0020')
    for prop1 in info1:
        prop1_ = prop1.replace("'","").split('=')
        try:
            if prop1_[0] == 'name':
                appInfo.append(prop1_[1])
            elif prop1_[0] == 'versionCode':
                appInfo.append(prop1_[1])
            elif prop1_[0] == 'versionName':
                appInfo.append(prop1_[1])
        except:
            pass

    for prop2 in temp:
        prop2_ = prop2.replace("'", "").split(':')
        try:
            if prop2_[0] == 'sdkVersion':
                appInfo.append(prop2_[1])
            elif prop2_[0] == 'targetSdkVersion':
                appInfo.append(prop2_[1])
            elif prop2_[0] == 'launchable-activity':
                info2 = prop2_[1].split('\u0020')
                for name in info2:
                    name_ = name.split('=')
                    if name_[0] == 'name':
                        appInfo.append(name_[1])
                        break
            elif prop2_[0] == 'uses-permission':
                info2 = prop2_[1].split('\u0020')
                for name in info2:
                    name_ = name.split('=')
                    if name_[0] == 'name':
                        appPerm.append(name_[1])
                        break

        except:
            pass

    return appInfo, appPerm