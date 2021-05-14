# APK Hack Tool
#
# -*- coding: utf-8 -*-
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5 import uic
import sys, os
import resource_rc
import Util
import webbrowser
import zipfile
import jks
import re

frm = uic.loadUiType("APKTool.ui")[0]

class MainWindow(QMainWindow, frm):
    def __init__(self):
        # initial setting
        self.toolPath = os.path.dirname(os.path.realpath(__file__))
        self.aapt = self.toolPath + '/lib/aapt2'
        self.zipalign = self.toolPath + '/lib/zipalign'
        self.signer = self.toolPath + '/lib/apksigner.jar'
        self.apktool = self.toolPath + '/lib/apktool.jar'
        self.apktoolHeapSize = '-Xmx512m'
        self.appExtension = ''
        self.decompileCommand = ''
        self.decompileOptions = []
        self.compileCommand = ''
        self.compileOptions = []
        self.zipalignCommand = ''
        self.signCommand = ''
        self.mode = 0
        self.baksmaliOptions = 'd'

        # load UI
        super().__init__()
        self.setupUi(self)
        self.setupFuctions()
        self.setupProcess()

    def setupFuctions(self):
        self.setFixedSize(800, 839)
        self.tabTool.setCurrentIndex(0)
        self.tabOptions.setCurrentIndex(0)

        self.btnBrowseApp.clicked.connect(self.analysisSelectedApp)
        self.btnBrowseDex.clicked.connect(self.setBaksmaliTarget)
        self.btnChangeBaksmali.clicked.connect(self.setBaksmaliOutputPath)
        self.btnBrowseDIs.clicked.connect(self.setSmaliTarget)
        self.btnChangeSmali.clicked.connect(self.setSmaliOutputPath)
        self.btnBaksmali.clicked.connect(lambda: self.procBaksmali.start(self.getBaksmaliCommand()))
        self.btnSmali.clicked.connect(lambda: self.procSmali.start(self.getSmaliCommand()))
        self.btnBrowseFW.clicked.connect(self.setFrameworksFile)
        self.btnChangeFWPath.clicked.connect(self.setFrameworksPath)
        self.btnInstallFW.clicked.connect(lambda: self.procFW.start(self.getFramworksCommand()))
        self.btnClearLog.clicked.connect(lambda: self.textLog.clear())
        self.btnDecompile.clicked.connect(lambda: self.procDecompile.start(self.decompileCommand))
        self.btnCompile.clicked.connect(lambda: self.procCompile.start(self.compileCommand))
        self.btnZipalign.clicked.connect(lambda: self.procZipalign.start(self.zipalignCommand))
        self.btnSign.clicked.connect(lambda: self.procSign.start(self.signCommand))
        self.btnKeyChange.clicked.connect(self.getKeystoreInfo)
        self.listAppPermissions.itemDoubleClicked.connect(self.checkPermissionInfo)
        self.clickable(self.iconPlayStore).connect(lambda: self.selectAppDownload(1))
        self.clickable(self.iconApkCombo).connect(lambda: self.selectAppDownload(2))

        self.g_op1.stateChanged.connect(self.checkHeapSize)
        self.d_op1.stateChanged.connect(self.updateToolCommand)
        self.d_op2.stateChanged.connect(self.updateToolCommand)
        self.d_op3.stateChanged.connect(self.updateToolCommand)
        self.d_op4.stateChanged.connect(self.updateToolCommand)
        self.d_op5.stateChanged.connect(self.updateToolCommand)
        self.d_op6.stateChanged.connect(self.updateToolCommand)
        self.d_op7.stateChanged.connect(self.updateToolCommand)
        self.c_op1.stateChanged.connect(self.updateToolCommand)
        self.c_op2.stateChanged.connect(self.updateToolCommand)
        self.c_op3.stateChanged.connect(self.updateToolCommand)
        self.c_op4.stateChanged.connect(self.updateToolCommand)
        self.c_op5.stateChanged.connect(self.updateToolCommand)
        self.c_op6.stateChanged.connect(self.updateToolCommand)
        self.odex_op.stateChanged.connect(self.checkOdex)

        self.textDecompOutputPath.setText(self.toolPath + '/1-Decompiled APKs/')
        self.texCompOutputPath.setText(self.toolPath + '/2-Recompiled APKs/')

    def setupProcess(self):
        self.procAdb = QProcess()
        self.procAdb.setProcessChannelMode(QProcess.MergedChannels)
        self.procAdb.readyRead.connect(self.checkAdbDevices)
        Util.startAdbServer()
        self.procAdb.start('adb devices -l')

        self.procApktool = QProcess()
        self.procApktool.setProcessChannelMode(QProcess.MergedChannels)
        self.procApktool.readyRead.connect(self.checkApktoolVersion)
        self.procApktool.start('java -jar "' + self.apktool + '" -version')

        self.procDecompile = QProcess()
        self.procDecompile.setProcessChannelMode(QProcess.MergedChannels)
        self.procDecompile.readyRead.connect(self.sendLogData)
        self.procDecompile.started.connect(self.decompileStart)
        self.procDecompile.finished.connect(self.decompileEnd)

        self.procCompile = QProcess()
        self.procCompile.setProcessChannelMode(QProcess.MergedChannels)
        self.procCompile.readyRead.connect(self.sendLogData)
        self.procCompile.started.connect(self.compileStart)
        self.procCompile.finished.connect(self.compileEnd)

        self.procZipalign = QProcess()
        self.procZipalign.setProcessChannelMode(QProcess.MergedChannels)
        self.procZipalign.readyRead.connect(self.sendLogData)
        self.procZipalign.started.connect(self.zipalignStart)
        self.procZipalign.finished.connect(self.zipalignEnd)

        self.procSign = QProcess()
        self.procSign.setProcessChannelMode(QProcess.MergedChannels)
        self.procSign.readyRead.connect(self.sendLogData)
        self.procSign.started.connect(self.signStart)
        self.procSign.finished.connect(self.signEnd)

        self.procBaksmali = QProcess()
        self.procBaksmali.setProcessChannelMode(QProcess.MergedChannels)
        self.procBaksmali.started.connect(lambda: self.statusBar.showMessage("Baksmaling.."))
        self.procBaksmali.finished.connect(lambda: self.statusBar.showMessage("Baksmali end", 3000))

        self.procSmali = QProcess()
        self.procSmali.setProcessChannelMode(QProcess.MergedChannels)
        self.procSmali.started.connect(lambda: self.statusBar.showMessage("Smaling.."))
        self.procSmali.finished.connect(lambda: self.statusBar.showMessage("Smali end", 3000))

        self.procFW = QProcess()
        self.procFW.setProcessChannelMode(QProcess.MergedChannels)
        self.procFW.started.connect(lambda: self.statusBar.showMessage("Frameworks installing.."))
        self.procFW.finished.connect(lambda: self.statusBar.showMessage("Frameworks install end", 3000))


    def clickable(self, widget):
        class Filter(QObject):

            clicked = pyqtSignal()
            def eventFilter(self, obj, event):
                if obj == widget:
                    if event.type() == QEvent.MouseButtonRelease:
                        if obj.rect().contains(event.pos()):
                            self.clicked.emit()
                            return True

                return False

        filter = Filter(widget)
        widget.installEventFilter(filter)
        return filter.clicked

    def analysisSelectedApp(self):
        qfd = QFileDialog()
        title = "Open APK/AAB file"
        filter = "APK file(*.apk);; AAB file(*.aab)"
        appPath = QFileDialog.getOpenFileName(qfd, title, "", filter)
        if appPath[0] != '':
            self.appExtension = os.path.splitext(os.path.basename(appPath[0]))[1]
            self.textAppPath.setText(appPath[0])
            self.textDecompName.setText(os.path.splitext(os.path.basename(appPath[0]))[0])
            self.textCompName.setText(os.path.splitext(os.path.basename(appPath[0]))[0])

            appInfo, appPerm = Util.getAppInformation(self.aapt, appPath[0])
            self.labelPackageName.setText(appInfo[0])
            self.labelVersionInfoName.setText(appInfo[1] + ' / ' + appInfo[2])
            self.labelMinSDKVersion.setText(appInfo[3])
            self.labelTargetSDKVersion.setText(appInfo[4])
            self.labelActivityName.setText(appInfo[5])
            for perm in appPerm:
                self.listAppPermissions.addItem(perm)

            with zipfile.ZipFile(appPath[0], 'r') as appZip:
                for fd in appZip.namelist():
                    if fd.find('app_icon.png') != -1:
                        qImg = QPixmap()
                        qImg.loadFromData(appZip.read(fd))
                        self.iconApp.setPixmap(qImg)
                        break

            self.updateToolCommand()

    def checkAdbDevices(self):
        try:
            out = re.split(r'[\r\n]+', str(self.procAdb.readAll().data(), encoding='utf-8').rstrip())

            for line in out[1:]:
                if not line.strip():
                    continue
                if 'offline' in line:
                    continue
                serial, _ = re.split(r'\s+', line, maxsplit=1)
                self.devicesList.addItem(serial)

        except Exception as ex:
            pass

    def checkApktoolVersion(self):
        try:
            version = str(self.procApktool.readAll().data(), encoding='utf-8').strip()
            self.labelApktoolVersion.setText('Apktool Version:\n' + version)

        except Exception as ex:
            pass

    def checkPermissionInfo(self):
        perm = self.listAppPermissions.currentItem().text()
        if perm.find('android.permission') != -1:
            webbrowser.open("https://developer.android.com/reference/android/Manifest.permission#" + str(perm).replace('android.permission.',''))

    def checkHeapSize(self):
        if self.g_op2.isChecked():
            self.apktoolHeapSize = '-Xmx' + str(self.textHeapSize.value) + 'm'
        else:
            self.apktoolHeapSize = '-Xmx512m'

    def checkOdex(self):
        if self.odex_op.isChecked():
            self.baksmaliOptions = 'de'
        else:
            self.baksmaliOptions = 'd'

    def updateToolCommand(self):
        if self.d_op1.isChecked():
            self.decompileOptions.append(self.d_op1.text())
        elif not self.d_op1.isChecked() and self.d_op1.text() in self.decompileOptions:
            self.decompileOptions.remove(self.d_op1.text())

        if self.d_op2.isChecked():
            self.decompileOptions.append(self.d_op2.text())
        elif not self.d_op2.isChecked() and self.d_op2.text() in self.decompileOptions:
            self.decompileOptions.remove(self.d_op2.text())

        if self.d_op3.isChecked():
            self.decompileOptions.append(self.d_op3.text())
        elif not self.d_op3.isChecked() and self.d_op3.text() in self.decompileOptions:
            self.decompileOptions.remove(self.d_op3.text())

        if self.d_op4.isChecked():
            self.decompileOptions.append(self.d_op4.text())
        elif not self.d_op4.isChecked() and self.d_op4.text() in self.decompileOptions:
            self.decompileOptions.remove(self.d_op4.text())

        if self.d_op5.isChecked():
            self.decompileOptions.append(self.d_op5.text())
        elif not self.d_op5.isChecked() and self.d_op5.text() in self.decompileOptions:
            self.decompileOptions.remove(self.d_op5.text())

        if self.d_op6.isChecked():
            self.decompileOptions.append(self.d_op6.text())
        elif not self.d_op6.isChecked() and self.d_op6.text() in self.decompileOptions:
            self.decompileOptions.remove(self.d_op6.text())

        if self.d_op7.isChecked():
            self.decompileOptions.append(self.d_op7.text())
        elif not self.d_op7.isChecked() and self.d_op7.text() in self.decompileOptions:
            self.decompileOptions.remove(self.d_op7.text())

        tempList = set(self.decompileOptions)
        self.decompileOptions = list(tempList)

        self.decompileCommand = 'java -jar "' + self.apktool + '" d "' + self.textAppPath.text() + \
                                '" -o "' + self.textDecompOutputPath.text() + self.textDecompName.text() + '/" ' + \
                                ' '.join(self.decompileOptions)

        if self.c_op1.isChecked():
            self.compileOptions.append(self.c_op1.text())
        elif not self.c_op1.isChecked() and self.c_op1.text() in self.compileOptions:
            self.compileOptions.remove(self.c_op1.text())

        if self.c_op2.isChecked():
            self.compileOptions.append(self.c_op2.text())
        elif not self.c_op2.isChecked() and self.c_op2.text() in self.compileOptions:
            self.compileOptions.remove(self.c_op2.text())

        if self.c_op3.isChecked():
            self.compileOptions.append(self.c_op3.text())
        elif not self.c_op3.isChecked() and self.c_op3.text() in self.compileOptions:
            self.compileOptions.remove(self.c_op3.text())

        if self.c_op4.isChecked():
            self.compileOptions.append(self.c_op4.text())
        elif not self.c_op4.isChecked() and self.c_op4.text() in self.compileOptions:
            self.compileOptions.remove(self.c_op4.text())

        if self.c_op5.isChecked():
            self.compileOptions.append(self.c_op5.text())
        elif not self.c_op5.isChecked() and self.c_op5.text() in self.compileOptions:
            self.compileOptions.remove(self.c_op5.text())

        if self.c_op6.isChecked():
            self.compileOptions.append(self.c_op6.text())
        elif not self.c_op6.isChecked() and self.c_op6.text() in self.compileOptions:
            self.compileOptions.remove(self.c_op6.text())

        tempList = set(self.compileOptions)
        self.compileOptions = list(tempList)

        self.compileCommand = 'java -jar "' + self.apktool + '" b "' + self.textDecompOutputPath.text() + self.textDecompName.text() + \
                              '/" -o "' + self.texCompOutputPath.text() + self.textCompName.text() + self.appExtension + '" ' + \
                              ' '.join(self.compileOptions)

        self.zipalignCommand = '"' + self.zipalign + '" -f -v 4 "' + self.texCompOutputPath.text() + self.textCompName.text() + self.appExtension + \
                               '" "' + self.texCompOutputPath.text() + self.textCompName.text() + '_temp"'

        self.generateSignCommand()

    def setBaksmaliTarget(self):
        qfd = QFileDialog()
        title = "Open Dex/odex/oat file"
        filter = "Dex file(*.dex *.odex *.oat);; All files(*.*)"
        dexPath = QFileDialog.getOpenFileName(qfd, title, "", filter)
        if dexPath[0] != '':
            self.textDexPath.setText(dexPath[0])
            self.textDexOutputPath.setText(os.path.dirname(dexPath[0]))

    def setBaksmaliOutputPath(self):
        qfd = QFileDialog()
        options = qfd.options()
        options |= qfd.ShowDirsOnly
        title = "Open Backsmali output directory"
        baksmaliPath = QFileDialog.getExistingDirectory(qfd, title, "", options=options)
        if baksmaliPath != '':
            self.textDexOutputPath.setText(baksmaliPath)

    def setSmaliTarget(self):
        qfd = QFileDialog()
        options = qfd.options()
        options |= qfd.ShowDirsOnly
        title = "Open disassembled directory for smali"
        smaliPath = QFileDialog.getExistingDirectory(qfd, title, "", options=options)
        if smaliPath != '':
            self.textDisPath.setText(smaliPath)
            self.textDisOutputPath.setText(smaliPath + '/classes.dex')

    def setSmaliOutputPath(self):
        qfd = QFileDialog()
        title = "Save Smali output file"
        filter = "Dex file(*.dex);; All files(*.*)"
        smaliOutputPath = QFileDialog.getSaveFileName(qfd, title, "", filter)
        if smaliOutputPath[0] != '':
            self.textDisOutputPath.setText(smaliOutputPath[0])

    def getBaksmaliCommand(self):
        if self.textDexPath.text() != '':
            return 'java -jar "' + self.toolPath + '/lib/baksmali.jar" ' + self.baksmaliOptions + ' "' + \
                            self.textDexPath.text() + '" -o "' + self.textDexOutputPath.text() + '"'

    def getSmaliCommand(self):
        if self.textDisPath.text() != '':
            return 'java -jar "' + self.toolPath + '/lib/smali.jar" a "' + self.textDisPath.text() + '" -o "' + self.textDisOutputPath.text() + '"'

    def setFrameworksFile(self):
        qfd = QFileDialog()
        title = "Open Frameworks file"
        filter = "Framworks file(*.apk);; All files(*.*)"
        fwPath = QFileDialog.getOpenFileName(qfd, title, "", filter)
        if fwPath[0] != '':
            self.textFWPath.setText(fwPath[0])

    def setFrameworksPath(self):
        qfd = QFileDialog()
        options = qfd.options()
        options |= qfd.ShowDirsOnly
        title = "Open Frameworks installed directory"
        fwInstalledPath = QFileDialog.getExistingDirectory(qfd, title, "", options=options)
        if fwInstalledPath != '':
            self.textFWInstallPath.setText(fwInstalledPath)

    def getFramworksCommand(self):
        if self.textFWPath.text() != '':
            return 'java -jar "' + self.apktool + '" if "' + self.textFWPath.text() + '" -p "' + self.textFWInstallPath.text() + '"'

    def getKeystoreInfo(self):
        if self.textMasterPassword.text():
            qfd = QFileDialog()
            title = "Open KeyStore file"
            filter = "Keystore file(*.jks *.keystore)"
            keyPath = QFileDialog.getOpenFileName(qfd, title, "", filter)
            if keyPath[0] != '':
                self.textKeystorePath.setText(keyPath[0])
                self.aliasList.clear()

                try:
                    key = []
                    ks = jks.KeyStore.load(self.textKeystorePath.text(), self.textMasterPassword.text())
                    for alias, pk in ks.private_keys.items():
                        key.append(pk.alias)
                    key = '|'.join(key)
                    alias = key.split('|')
                    for i in alias:
                        self.aliasList.addItem(i)

                    self.generateSignCommand()

                except:
                    self.statusBar.showMessage("Keystore password is wrong", 3000)
                    pass

    def generateSignCommand(self):
        if self.s_op2.isChecked():
            self.signCommand = 'java -jar "' + self.signer + '" sign -v --out "' + self.texCompOutputPath.text() + self.textCompName.text() + self.appExtension + '" ' + \
                               '--ks "' + self.textKeystorePath.text() + '" --ks-pass pass:' + self.textMasterPassword.text() + ' --ks-key-alias "' + self.aliasList.currentText() + '" --key-pass pass:' + \
                               self.textAliasPassword.text() + ' "' + self.texCompOutputPath.text() + self.textCompName.text() + '_temp"'
        else:
            self.signCommand = 'java -jar "' + self.signer + '" sign -v --out "' + self.texCompOutputPath.text() + self.textCompName.text() + self.appExtension + '" ' + \
                               '--ks "' + self.toolPath + '/lib/debug.keystore' + '" --ks-pass pass:android --ks-key-alias "androiddebugkey" --key-pass pass:' + \
                               'android "' + self.texCompOutputPath.text() + self.textCompName.text() + '_temp"'

    def selectAppDownload(self, num):
        if self.labelPackageName.text() != '---':
            if num == 1:
                webbrowser.open("https://play.google.com/store/apps/details?id=" + self.labelPackageName.text())
            elif num == 2:
                webbrowser.open("https://apkcombo.com/en-dk/apk-downloader/?q=" + self.labelPackageName.text())

    def changeBtnStatus(self):
        if self.btnDecompile.isEnabled():
            self.btnDecompile.setEnabled(False)
            self.btnCompile.setEnabled(False)
            self.btnZipalign.setEnabled(False)
            self.btnSign.setEnabled(False)
            self.btnInsApk.setEnabled(False)
            self.btnInsAab.setEnabled(False)
        else:
            self.btnDecompile.setEnabled(True)
            self.btnCompile.setEnabled(True)
            self.btnZipalign.setEnabled(True)
            self.btnSign.setEnabled(True)
            self.btnInsApk.setEnabled(True)
            self.btnInsAab.setEnabled(True)

    def sendLogData(self):
        if self.mode == 1:
            result = str(self.procDecompile.readAll().data(), encoding='utf-8').strip()
        elif self.mode == 2:
            result = str(self.procCompile.readAll().data(), encoding='utf-8').strip()
        elif self.mode == 3:
            result = str(self.procZipalign.readAll().data(), encoding='utf-8').strip()
        elif self.mode == 4:
            result = str(self.procSign.readAll().data(), encoding='utf-8').strip()

        self.textLog.append(result)
        self.textLog.moveCursor(QTextCursor.End)

    def decompileStart(self):
        self.statusBar.showMessage("Decompiling..")
        self.mode = 1
        self.changeBtnStatus()

    def decompileEnd(self):
        self.statusBar.showMessage("Decompile end", 3000)
        self.textLog.append('')
        self.textLog.moveCursor(QTextCursor.End)
        self.mode = 0
        self.changeBtnStatus()

    def compileStart(self):
        self.statusBar.showMessage("Compiling..")
        self.mode = 2
        self.changeBtnStatus()

    def compileEnd(self):
        self.statusBar.showMessage("Compile end", 3000)
        self.textLog.append('')
        self.textLog.moveCursor(QTextCursor.End)
        self.mode = 0
        self.changeBtnStatus()

        if self.z_op1.isChecked():
            self.procZipalign.start(self.zipalignCommand)

        if self.s_op1.isChecked():
            self.procSign.start(self.signCommand)

    def zipalignStart(self):
        self.statusBar.showMessage("Zipaligning..")
        self.mode = 3
        self.changeBtnStatus()

    def zipalignEnd(self):
        self.statusBar.showMessage("Zipalign end", 3000)
        self.textLog.append('')
        self.textLog.moveCursor(QTextCursor.End)
        self.mode = 0
        self.changeBtnStatus()

    def signStart(self):
        self.statusBar.showMessage("Signing..")
        self.mode = 4
        self.changeBtnStatus()

    def signEnd(self):
        self.statusBar.showMessage("Sign end", 3000)
        self.textLog.append('')
        self.textLog.moveCursor(QTextCursor.End)
        self.mode = 0
        self.changeBtnStatus()
        os.remove(self.texCompOutputPath.text() + self.textCompName.text() + '_temp')
        os.remove(self.texCompOutputPath.text() + self.textCompName.text() + self.appExtension + '.idsig')




if __name__ == "__main__":
    app = QApplication(sys.argv)
    QApplication.setStyle(QStyleFactory.create('Fusion'))
    myApp = MainWindow()
    myApp.show()
    app.exec_()

