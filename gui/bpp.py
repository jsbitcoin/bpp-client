#!/usr/bin/python
# -*- coding: utf-8 -*-
# BPP - lightweight XMPP Bitcoin payment protocol client
# Copyright (C) 2014 jsbitcoin

import sys
import os
import json
import string
import random
import sleekxmpp
import electrum.deterministic as Btclib
import sqlite3 as Db
import logging
from PySide import QtCore, QtGui

# Electrum imports
from decimal import Decimal
_ = lambda x:x
from electrum import mnemonic_encode, WalletStorage, Wallet
from electrum.util import format_satoshis, set_verbosity
from electrum.bitcoin import is_valid
from electrum.network import filter_protocol
import datetime


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setWindowModality(QtCore.Qt.NonModal)
        MainWindow.resize(697, 485)
        MainWindow.setMinimumSize(QtCore.QSize(544, 0))
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtGui.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        self.tabWidget = QtGui.QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName("tabWidget")
        self.tabhome = QtGui.QWidget()
        self.tabhome.setObjectName("tabhome")
        self.formLayout_2 = QtGui.QFormLayout(self.tabhome)
        self.formLayout_2.setFieldGrowthPolicy(QtGui.QFormLayout.AllNonFixedFieldsGrow)
        self.formLayout_2.setObjectName("formLayout_2")
        self.label_3 = QtGui.QLabel(self.tabhome)
        self.label_3.setObjectName("label_3")
        self.formLayout_2.setWidget(0, QtGui.QFormLayout.LabelRole, self.label_3)
        self.bppidcb = QtGui.QComboBox(self.tabhome)
        self.bppidcb.setObjectName("bppidcb")
        self.formLayout_2.setWidget(0, QtGui.QFormLayout.FieldRole, self.bppidcb)
        self.newbppidbt = QtGui.QPushButton(self.tabhome)
        self.newbppidbt.setObjectName("newbppidbt")
        self.formLayout_2.setWidget(2, QtGui.QFormLayout.FieldRole, self.newbppidbt)
        self.bppidcntbt = QtGui.QPushButton(self.tabhome)
        self.bppidcntbt.setObjectName("bppidcntbt")
        self.formLayout_2.setWidget(3, QtGui.QFormLayout.FieldRole, self.bppidcntbt)
        self.label_8 = QtGui.QLabel(self.tabhome)
        self.label_8.setMinimumSize(QtCore.QSize(0, 0))
        self.label_8.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_8.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_8.setObjectName("label_8")
        self.formLayout_2.setWidget(4, QtGui.QFormLayout.FieldRole, self.label_8)
        self.bppidsec = QtGui.QLineEdit(self.tabhome)
        self.bppidsec.setReadOnly(True)
        self.bppidsec.setObjectName("bppidsec")
        self.formLayout_2.setWidget(5, QtGui.QFormLayout.FieldRole, self.bppidsec)
        self.addbppidbt = QtGui.QPushButton(self.tabhome)
        self.addbppidbt.setObjectName("addbppidbt")
        self.formLayout_2.setWidget(1, QtGui.QFormLayout.FieldRole, self.addbppidbt)
        self.tabWidget.addTab(self.tabhome, "")
        self.tabsend = QtGui.QWidget()
        self.tabsend.setObjectName("tabsend")
        self.formLayout = QtGui.QFormLayout(self.tabsend)
        self.formLayout.setFieldGrowthPolicy(QtGui.QFormLayout.AllNonFixedFieldsGrow)
        self.formLayout.setObjectName("formLayout")
        self.label = QtGui.QLabel(self.tabsend)
        self.label.setObjectName("label")
        self.formLayout.setWidget(2, QtGui.QFormLayout.LabelRole, self.label)
        self.sendaddr = QtGui.QLineEdit(self.tabsend)
        self.sendaddr.setObjectName("sendaddr")
        self.formLayout.setWidget(2, QtGui.QFormLayout.FieldRole, self.sendaddr)
        self.label_4 = QtGui.QLabel(self.tabsend)
        self.label_4.setObjectName("label_4")
        self.formLayout.setWidget(3, QtGui.QFormLayout.LabelRole, self.label_4)
        self.sendval = QtGui.QLineEdit(self.tabsend)
        self.sendval.setObjectName("sendval")
        self.formLayout.setWidget(3, QtGui.QFormLayout.FieldRole, self.sendval)
        self.label_7 = QtGui.QLabel(self.tabsend)
        self.label_7.setObjectName("label_7")
        self.formLayout.setWidget(4, QtGui.QFormLayout.LabelRole, self.label_7)
        self.sendref = QtGui.QLineEdit(self.tabsend)
        self.sendref.setObjectName("sendref")
        self.formLayout.setWidget(4, QtGui.QFormLayout.FieldRole, self.sendref)
        self.sendbt = QtGui.QPushButton(self.tabsend)
        self.sendbt.setObjectName("sendbt")
        self.formLayout.setWidget(5, QtGui.QFormLayout.FieldRole, self.sendbt)
        self.tabWidget.addTab(self.tabsend, "")
        self.tab = QtGui.QWidget()
        self.tab.setObjectName("tab")
        self.gridLayout_3 = QtGui.QGridLayout(self.tab)
        self.gridLayout_3.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_3.setSpacing(0)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.addrs = QtGui.QTableWidget(self.tab)
        self.addrs.setSelectionMode(QtGui.QAbstractItemView.NoSelection)
        self.addrs.setShowGrid(False)
        self.addrs.setObjectName("addrs")
        self.addrs.setColumnCount(1)
        self.addrs.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.addrs.setHorizontalHeaderItem(0, item)
        self.addrs.horizontalHeader().setStretchLastSection(True)
        self.addrs.verticalHeader().setVisible(False)
        self.gridLayout_3.addWidget(self.addrs, 0, 0, 1, 1)
        self.tabWidget.addTab(self.tab, "")
        self.tabtxs = QtGui.QWidget()
        self.tabtxs.setObjectName("tabtxs")
        self.gridLayout_2 = QtGui.QGridLayout(self.tabtxs)
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_2.setSpacing(0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.txhist = QtGui.QTableWidget(self.tabtxs)
        self.txhist.setSelectionMode(QtGui.QAbstractItemView.NoSelection)
        self.txhist.setShowGrid(False)
        self.txhist.setObjectName("txhist")
        self.txhist.setColumnCount(5)
        self.txhist.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.txhist.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.txhist.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.txhist.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem()
        self.txhist.setHorizontalHeaderItem(3, item)
        item = QtGui.QTableWidgetItem()
        self.txhist.setHorizontalHeaderItem(4, item)
        self.txhist.horizontalHeader().setCascadingSectionResizes(False)
        self.txhist.horizontalHeader().setStretchLastSection(True)
        self.txhist.verticalHeader().setVisible(False)
        self.gridLayout_2.addWidget(self.txhist, 0, 0, 1, 1)
        self.tabWidget.addTab(self.tabtxs, "")
        self.gridLayout.addWidget(self.tabWidget, 3, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusBar = QtGui.QStatusBar(MainWindow)
        self.statusBar.setObjectName("statusBar")
        MainWindow.setStatusBar(self.statusBar)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QtGui.QApplication.translate("MainWindow", "The Bitcoin payment protocol", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(QtGui.QApplication.translate("MainWindow", "BPP ID:", None, QtGui.QApplication.UnicodeUTF8))
        self.newbppidbt.setText(QtGui.QApplication.translate("MainWindow", "Create a new account", None, QtGui.QApplication.UnicodeUTF8))
        self.bppidcntbt.setText(QtGui.QApplication.translate("MainWindow", "Connect", None, QtGui.QApplication.UnicodeUTF8))
        self.label_8.setText(QtGui.QApplication.translate("MainWindow", "Share this secure address to receive payment:", None, QtGui.QApplication.UnicodeUTF8))
        self.addbppidbt.setText(QtGui.QApplication.translate("MainWindow", "Add an existing account", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tabhome), QtGui.QApplication.translate("MainWindow", "Home", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("MainWindow", "Address: ", None, QtGui.QApplication.UnicodeUTF8))
        self.label_4.setText(QtGui.QApplication.translate("MainWindow", "Amount:", None, QtGui.QApplication.UnicodeUTF8))
        self.label_7.setText(QtGui.QApplication.translate("MainWindow", "Reference:", None, QtGui.QApplication.UnicodeUTF8))
        self.sendbt.setText(QtGui.QApplication.translate("MainWindow", "Send", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tabsend), QtGui.QApplication.translate("MainWindow", "Send", None, QtGui.QApplication.UnicodeUTF8))
        self.addrs.horizontalHeaderItem(0).setText(QtGui.QApplication.translate("MainWindow", "Addresses", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), QtGui.QApplication.translate("MainWindow", "Receive", None, QtGui.QApplication.UnicodeUTF8))
        self.txhist.horizontalHeaderItem(0).setText(QtGui.QApplication.translate("MainWindow", "Date", None, QtGui.QApplication.UnicodeUTF8))
        self.txhist.horizontalHeaderItem(1).setText(QtGui.QApplication.translate("MainWindow", "Reference", None, QtGui.QApplication.UnicodeUTF8))
        self.txhist.horizontalHeaderItem(2).setText(QtGui.QApplication.translate("MainWindow", "From", None, QtGui.QApplication.UnicodeUTF8))
        self.txhist.horizontalHeaderItem(3).setText(QtGui.QApplication.translate("MainWindow", "To", None, QtGui.QApplication.UnicodeUTF8))
        self.txhist.horizontalHeaderItem(4).setText(QtGui.QApplication.translate("MainWindow", "Amount", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tabtxs), QtGui.QApplication.translate("MainWindow", "History", None, QtGui.QApplication.UnicodeUTF8))


class InvokeEvent(QtCore.QEvent):
    EVENT_TYPE = QtCore.QEvent.Type(QtCore.QEvent.registerEventType())

    def __init__(self, fn, *args, **kwargs):
        QtCore.QEvent.__init__(self, InvokeEvent.EVENT_TYPE)
        self.fn = fn
        self.args = args
        self.kwargs = kwargs


class Invoker(QtCore.QObject):
    def event(self, event):
        event.fn(*event.args, **event.kwargs)

        return True

_invoker = Invoker()
waitCondition = QtCore.QWaitCondition()
mutex = QtCore.QMutex()

def invoke_gui(fn, *args, **kwargs):
    QtCore.QCoreApplication.postEvent(_invoker,
        InvokeEvent(fn, *args, **kwargs))

class BPPClient(QtGui.QMainWindow):
    def __init__(self, parent=None):
	super(BPPClient, self).__init__(parent)
	self.ui =  Ui_MainWindow()
	self.ui.setupUi(self)
	self.btcrpc = None
	self.bppcnx = None
	self.cfgmain = {"priv_seed" : None, "master_pub_key" : None, "keysign" : None}
	self.cfgbpp = []
	self.mpkbpp = None
	self.mpkbtc = None
	self.keysign = None
	self.balance = ""
	self.wallet = None
	self.confpayhist = ()
	self.pendpayhist = {}
	
	self.get_balance = None
	
	self.ui.newbppidbt.clicked.connect(newbppid)
	self.ui.addbppidbt.clicked.connect(addbppid)
	self.ui.bppidcntbt.clicked.connect(bppidcnt)
	self.ui.sendbt.clicked.connect(sendpay)
	
	txhm = self.ui.txhist
	txhm.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
	txhm.customContextMenuRequested.connect(self.handletxhm)
	
	self.payhist = Db.connect(os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'bpp_data', 'pay_history'))

    def handletxhm(self, pos):
	try:
	    row = (self.ui.txhist.rowCount()-1)-self.ui.txhist.itemAt(pos).row()
	    if self.confpayhist[row][0]: 
		addr = self.confpayhist[row][1].split('/')[3] if self.confpayhist[row][1] != '' else None 
	    if addr:
		menu = QtGui.QMenu()
        	d = menu.addAction('Details')
        	r = menu.addAction('Retransmit')
        	act = menu.exec_(QtGui.QCursor.pos())
		if act == d:
		    QtGui.QMessageBox.information(bppclient, 'Details', "%s bitcoins was sent to this address: %s\nThe return address is: %s"%(format_satoshis(abs(self.confpayhist[row][7])), addr,self.confpayhist[row][5]), QtGui.QMessageBox.Ok)
		if act == r:
		    try:
		        bppclient.bppcnx.send_message(mto=self.confpayhist[row][3], mbody=json.dumps({"TYPE" : "PAYMENT", "DATA" : {"PATH" : self.confpayhist[row][1],
                             "TXIN" : self.confpayhist[row][0], "REF" : self.confpayhist[row][4],
                             "RETADDR" : self.confpayhist[row][5]}}))
		        QtGui.QMessageBox.information(bppclient, 'Retransmit', "The payment have been correctly retransmited.", QtGui.QMessageBox.Ok)
		    except (sleekxmpp.exceptions.XMPPError):
        		QtGui.QMessageBox.warning(bppclient, 'Retransmit', "An error have occured.", QtGui.QMessageBox.Ok)
	except (IndexError, AttributeError):
	    return
	

class AddIdDialog(QtGui.QDialog):
    def __init__(self):
        QtGui.QDialog.__init__(self)
	self.setWindowTitle(u"Add an existing account")
	self.resize(350, 150)
	self.l1 = QtGui.QLabel(self)
	self.l1.setText(u"Your XMPP Address:")
        self.usr = QtGui.QLineEdit(self)
	self.l2 = QtGui.QLabel(self)
	self.l2.setText(u"Your Password:")
        self.pwd = QtGui.QLineEdit(self)
	self.pwd.setEchoMode(QtGui.QLineEdit.Password)
        self.buttonAdd = QtGui.QPushButton('Add', self)
        self.buttonAdd.clicked.connect(self.handleAdd)
        layout = QtGui.QVBoxLayout(self)
	layout.addWidget(self.l1)
        layout.addWidget(self.usr)
	layout.addWidget(self.l2)
        layout.addWidget(self.pwd)
        layout.addWidget(self.buttonAdd)

    def handleAdd(self):
            self.accept()

class BPPxmpp(sleekxmpp.ClientXMPP):
    def __init__(self, jid, password):
        sleekxmpp.ClientXMPP.__init__(self, jid, password)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("register", self.register)
	self.add_event_handler("no_auth", self.noauth)
	self.add_event_handler("socket_error", self.socketerror)
        self.add_event_handler("message", self.message)
	self.add_event_handler("session_end", self.end)
        self.genmkp_timer = QtCore.QTimer()
        self.genmkp_timer.timeout.connect(self.genmpk)
	self.genmkp_timer.start(300000)
	self.connected = False
	self.addid = False
	self.reconnect_delay = 1
	self.reconnect_max_delay = 1

    def start(self, event):
        self.send_presence()
	self.connected = True
        invoke_gui(updateStatusBar)
        self.genmpk()
	waitCondition.wakeAll()
	if self.addid:
	    bppclient.cfgbpp.append({"bppid" : self.addid['usr'], "password" : self.addid['pwd']})
            save_cfg()
            bppclient.ui.bppidcb.addItem(self.addid['usr'])
            bppclient.ui.bppidcb.setCurrentIndex(bppclient.ui.bppidcb.count()-1)
	    self.addid = False
            invoke_gui(QtGui.QMessageBox.information,bppclient, 'Add an existing account', "Your XMPP address have been added.", QtGui.QMessageBox.Ok)

    def end(self, event):
        self.genmkp_timer.stop()
	self.connected = False
	invoke_gui(updateStatusBar)
	waitCondition.wakeAll()

    def noauth(self, event):
        self.addid = False
        invoke_gui(QtGui.QMessageBox.warning,bppclient, 'Add an existing account', "Cannot connect to the server.", QtGui.QMessageBox.Ok)

    def socketerror(self, event):
	if event[0] in (101, 111, 22) and self.connected == 2:
	    waitCondition.wakeAll()
	    self.disconnect()
	    self.connected = False
            bppclient.bppcnx = None
	self.connected = 2
        
    def message(self, msg):
        if msg['type'] == 'normal':
	    try:
                req = json.loads(msg['body'])
                if req['TYPE'] == 'PAYMENT':
		    try:
		        p1, p2, p3, addr = req['DATA']['PATH'].split('/')
		        frm, to = msg['from'].bare, self.boundjid.bare
		        if Btclib.pubkey_to_address(Btclib.bip32_extract_key(Btclib.subkey_for_path(bppclient.mpkbtc, p1+'/'+p2+'/'+p3))) != addr: return
		        if req['DATA']['TXIN'] in bppclient.pendpayhist: return"mm" 
		        if req['DATA']['TXIN'] in map(lambda x:x[0], bppclient.confpayhist): return
		        invoke_gui(insertPendPay, (req['DATA']['TXIN'],req['DATA']['PATH'],frm,to,req['DATA']['REF'],req['DATA']['RETADDR']))
		        bppclient.pendpayhist[req['DATA']['TXIN']] = (req['DATA']['PATH'],frm,to,req['DATA']['REF'],req['DATA']['RETADDR'])
		        bppclient.wallet.import_key_bip32(addr, p1+'/'+p2+'/'+p3, None)
		    except: return
	    except ValueError: return

    def genmpk(self):
        p1 = str(random.randrange(2**31-1))
        p2 = str(random.randrange(2**31-1))
        mpk = p1+'/'+p2+'/'+Btclib.subkey_for_path(bppclient.mpkbtc, p1+'/'+p2)
        vcard = self['xep_0054'].stanza.VCardTemp()
        vcard['FN'] = 'BPP Client'
        vcard['JABBERID'] = self.boundjid.bare
        vcard['NOTE'] = '{"BITCOIN_MPK" : "'+mpk+'", '
        vcard['NOTE'] += '"BITCOIN_SIGN" : "'+Btclib.ecdsa_sign(mpk, bppclient.keysign)+'"}'
        self['xep_0054'].publish_vcard(vcard)

    def register(self, iq):
        resp = self.Iq()
        resp['type'] = 'set'
        resp['register']['username'] = self.boundjid.user
        resp['register']['password'] = self.password

        try:
            resp.send(now=True)
            self.regstatus = 1
            logging.info("Account created for %s!" % self.boundjid)
            waitCondition.wakeAll()
        except sleekxmpp.exceptions.IqError as e:
            self.regstatus = 2
            logging.error("Could not register account: %s" %
                    e.iq['error']['code'])
            self.disconnect()
            waitCondition.wakeAll()
        except sleekxmpp.exceptions.IqTimeout:
            self.regstatus = 3
            logging.error("No response from server.")
            self.disconnect()
            waitCondition.wakeAll()

def sendpay():
    sendaddr = bppclient.ui.sendaddr.text().split('&')
    sendval = bppclient.ui.sendval.text()
    sendref = bppclient.ui.sendref.text()
    if len(sendaddr) == 2:
        check = '1'+sendaddr[1]
    else:
        check = '1'+sendaddr[0].split('@')[0]
    sendaddr = sendaddr[0]
    try: #Bitcoin Address
	if Btclib.get_version_byte(sendaddr) == 0:
	    check = 'B'
    except AssertionError:
        pass
    if not '@' in sendaddr and check != 'B':
	QtGui.QMessageBox.warning(bppclient, 'Payment', "%s is not a BPP valid address." % sendaddr, QtGui.QMessageBox.Ok)
        return
    try: #BPP ID
        if check != 'B' and Btclib.get_version_byte(check) != 0:
            check = ""
    except AssertionError:
        check = ""
    if check == "":
        if QtGui.QMessageBox.Cancel == QtGui.QMessageBox.warning(bppclient, 'Payment', "There are not a valid security code entered. Do you want to send the payment without asserting the destination address ?", QtGui.QMessageBox.Ok | QtGui.QMessageBox.Cancel):
            return
    try:
        result = json.loads(bppclient.bppcnx['xep_0054'].get_vcard(sendaddr)['vcard_temp']['NOTE']) if check != 'B' else None
        if check != "" and check != 'B' and Btclib.hex_to_b58check(Btclib.ecdsa_recover(str(result['BITCOIN_MPK']), str(result['BITCOIN_SIGN']))[2:32]) != check:
            QtGui.QMessageBox.critical(bppclient, 'Payment', "The security of the payment address is corrupted.", QtGui.QMessageBox.Ok)
            return
	try:
            amount = int(Decimal(sendval) * 100000000)
	    if amount == 0: raise Exception
        except Exception:
            QtGui.QMessageBox.warning(bppclient, 'Payment', "Invalid Amount.", QtGui.QMessageBox.Ok)
            return
	if check != 'B':
            p1, p2, mpk = result['BITCOIN_MPK'].split('/')
            p3 = random.randrange(2**31-1)
        addr = Btclib.pubkey_to_address(Btclib.bip32_extract_key(Btclib.bip32_ckd(mpk, p3))) if check != 'B' else sendaddr
	try:
	    tx = bppclient.wallet.mktx([(addr,amount)],None)
	except ValueError:
	    QtGui.QMessageBox.warning(bppclient, 'Payment', "Not enough funds.", QtGui.QMessageBox.Ok)
            return
	txin = tx.inputs[0].get('prevout_hash')
	if check != 'B':
            paymsg = json.dumps({"TYPE" : "PAYMENT", "DATA" : {"PATH" : p1+'/'+p2+'/'+str(p3)+'/'+addr,
                             "TXIN" : txin, "REF" : sendref,
                             "RETADDR" : bppclient.ui.bppidsec.text()}})
            bppclient.bppcnx.send_message(mto=sendaddr, mbody=paymsg)
	    insertPendPay((txin,p1+'/'+p2+'/'+str(p3)+'/'+addr,bppclient.bppcnx.boundjid.bare,sendaddr,sendref,bppclient.ui.bppidsec.text()),)
	    bppclient.pendpayhist[txin] = (p1+'/'+p2+'/'+str(p3)+'/'+addr,bppclient.bppcnx.boundjid.bare,sendaddr,sendref,bppclient.ui.bppidsec.text())
	else:
	    insertPendPay((txin,'',tx.inputs[0].get('address'),addr,sendref,''),)
	    bppclient.pendpayhist[txin] = ('',tx.inputs[0].get('address'),addr,sendref,'')
	g, o = bppclient.wallet.sendtx(tx)
	if g:  
            QtGui.QMessageBox.information(bppclient, 'Payment', "Your payment have been sent.", QtGui.QMessageBox.Ok)
	else:
	    QtGui.QMessageBox.information(bppclient, 'Payment', o, QtGui.QMessageBox.Ok)
    except (sleekxmpp.exceptions.XMPPError, KeyError, TypeError):
        QtGui.QMessageBox.warning(bppclient, 'Payment', "%s is not a BPP valid address." % sendaddr, QtGui.QMessageBox.Ok)
        return

def bppidcnt():
    if len(bppclient.cfgbpp) == 0:
	QtGui.QMessageBox.warning(bppclient, 'Connection', "You must first create or add a new BPP ID.", QtGui.QMessageBox.Ok)
	return
    bppid = bppclient.ui.bppidcb.currentText()
    password = next(x["password"] for x in bppclient.cfgbpp if x["bppid"] == bppid)
    if bppclient.bppcnx != None: bppclient.bppcnx.disconnect()
    bppclient.bppcnx = BPPxmpp(bppid, password)
    bppclient.bppcnx.register_plugin('xep_0054')
    bppclient.bppcnx.connect()
    bppclient.bppcnx.process()
    user = bppid.split('@')[0]
    sec = Btclib.hex_to_b58check(Btclib.privkey_to_pubkey(bppclient.keysign)[2:32])[1:]
    if user == sec:
        bppclient.ui.bppidsec.setText(bppid)
    else:
        bppclient.ui.bppidsec.setText(bppid + '&' + sec)

def addbppid():
     addid = AddIdDialog()
     if addid.exec_() == QtGui.QDialog.Accepted:
	bppid = addid.usr.text()
	password = addid.pwd.text()
	if bppclient.bppcnx != None: bppclient.bppcnx.disconnect()
	try:
            bppclient.bppcnx = BPPxmpp(bppid, password)
	except sleekxmpp.jid.InvalidJID:
	    QtGui.QMessageBox.warning(bppclient, 'Add an existing account', "Domain contains illegar characters.", QtGui.QMessageBox.Ok)
	    return
	bppclient.bppcnx.addid = {'usr':bppid, 'pwd':password}
        bppclient.bppcnx.register_plugin('xep_0054')
	bppclient.bppcnx.connect(reattempt=False)
	bppclient.bppcnx.process()

def newbppid():
    if bppclient.cfgmain["priv_seed"] == "":
        QtGui.QMessageBox.critical(bppclient, 'Registration', "No seed in config file to generate password.", QtGui.QMessageBox.Ok)
        return
    bppid, ok = QtGui.QInputDialog.getText(bppclient, 'Create a new BPP ID', 'Enter your new BPP ID: (like username@example.com)')
    if ok and bppid != '':
        password = Btclib.bip32_ckd(bppclient.mpkbpp, Btclib.decode(Btclib.sha256(bppid)[0:6],16))[-28:]
        bppclient.bppcnx = BPPxmpp(bppid, password)
        bppclient.bppcnx.register_plugin('xep_0030') # Service Discovery
        bppclient.bppcnx.register_plugin('xep_0004') # Data forms
        bppclient.bppcnx.register_plugin('xep_0066') # Out-of-band Data
        bppclient.bppcnx.register_plugin('xep_0077') # In-band Registration
        bppclient.bppcnx.register_plugin('xep_0054') # Vcard
        bppclient.bppcnx['xep_0077'].force_registration = True
	bppclient.bppcnx.connect(reattempt=False)
        bppclient.bppcnx.process()
        mutex.lock()
        waitCondition.wait(mutex)
        mutex.unlock()
        if bppclient.bppcnx.regstatus == 1:
            bppclient.cfgbpp.append({"bppid" : str(bppid), "password" : password})
            save_cfg()
            bppclient.ui.bppidcb.addItem(str(bppid))
            bppclient.ui.bppidcb.setCurrentIndex(bppclient.ui.bppidcb.count()-1)
            QtGui.QMessageBox.warning(bppclient, 'Registration', "Your BPP ID have been created.", QtGui.QMessageBox.Ok)
	    user = bppid.split('@')[0]
    	    sec = Btclib.hex_to_b58check(Btclib.privkey_to_pubkey(bppclient.keysign)[2:32])[1:]
    	    if user == sec:
        	bppclient.ui.bppidsec.setText(bppid)
    	    else:
        	bppclient.ui.bppidsec.setText(bppid + '&' + sec)
        elif bppclient.bppcnx.regstatus == 2:
            QtGui.QMessageBox.warning(bppclient, 'Registration', "This BPP ID is already in use.", QtGui.QMessageBox.Ok)
        elif bppclient.bppcnx.regstatus == 3:
            QtGui.QMessageBox.warning(bppclient, 'Registration', "No response frome the server. TimeOut.", QtGui.QMessageBox.Ok)
        
def updateStatusBar():
    bppclient.statusBar().showMessage(bppclient.get_balance()+u' | '+("XMPP connected" if bppclient.bppcnx and bppclient.bppcnx.connected else "No XMPP connection"))

def updateReceiveAddrs():
    bppclient.ui.addrs.setRowCount(0)
    for address in bppclient.wallet.get_account_addresses(0, False):
        bppclient.ui.addrs.insertRow(0)
	bppclient.ui.addrs.setItem(0, 0, QtGui.QTableWidgetItem(address))

def updateHistory():
    bppclient.ui.txhist.setRowCount(0)
    t = None
    c = 0
    for t in bppclient.confpayhist:
	c += 1
	bppclient.ui.txhist.insertRow(0)
	bppclient.ui.txhist.setItem(0, 0, QtGui.QTableWidgetItem(t[6]))
	bppclient.ui.txhist.setItem(0, 1, QtGui.QTableWidgetItem(t[4]))
	bppclient.ui.txhist.setItem(0, 2, QtGui.QTableWidgetItem(t[2]))
	bppclient.ui.txhist.setItem(0, 3, QtGui.QTableWidgetItem(t[3]))
	bppclient.ui.txhist.setItem(0, 4, QtGui.QTableWidgetItem(format_satoshis(t[7])))
    newtx = False
    cur = bppclient.payhist.cursor()
    for item in bppclient.wallet.get_tx_history()[c:]:
        tx_hash, conf, is_mine, value, fee, balance, timestamp = item
	txin = bppclient.wallet.transactions.get(tx_hash).inputs[0].get('prevout_hash')
	print tx_hash, conf, value
        if conf > 0:
            try:
                time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
            except Exception:
                time_str = "------"
	    try:
		if txin in bppclient.pendpayhist:
		    i = bppclient.pendpayhist[txin]
		    cur.execute("INSERT INTO ConfPay VALUES(?, ?, ?, ?, ?, ?, ?, ?)", (txin,i[0],i[1],i[2],i[3],i[4], time_str, value))
		    
		    cur.execute("DELETE FROM PendPay WHERE `Txin` = '%s'"%txin)
		    ref, frm, to = i[3],i[1],i[2]
		    bppclient.confpayhist += ((txin,i[0],i[1],i[2],i[3],i[4], time_str, value),)
		    del bppclient.pendpayhist[txin]
		else:
		    oaddr = bppclient.wallet.transactions.get(tx_hash).outputs[0][0]
		    iaddr = bppclient.wallet.transactions.get(tx_hash).inputs[0].get('address')
		    cur.execute("INSERT INTO ConfPay VALUES(?, ?, ?, ?, ?, ?, ?, ?)", (txin,'',iaddr, oaddr, '', '', time_str, value))
		    ref, frm, to = '',iaddr,oaddr
		    bppclient.confpayhist += ((txin,'',iaddr,oaddr,'','', time_str, value),)
    	    except Db.Error, e:
        	if bppclient.payhist:
                    bppclient.payhist.rollback()
        	QtGui.QMessageBox.critical(bppclient, 'Error', e.args[0], QtGui.QMessageBox.Ok)
        else:
            time_str = 'unverified' if conf == -1 else 'pending'
	    if txin in bppclient.pendpayhist:
		i = bppclient.pendpayhist[txin]
		ref, frm, to = i[3],i[1],i[2]
	    else:
		oaddr = bppclient.wallet.transactions.get(tx_hash).outputs[0][0]
		iaddr = bppclient.wallet.transactions.get(tx_hash).inputs[0].get('address')
		ref, frm, to = '',iaddr,oaddr

	bppclient.ui.txhist.insertRow(0)
	bppclient.ui.txhist.setItem(0, 0, QtGui.QTableWidgetItem(time_str))
	bppclient.ui.txhist.setItem(0, 1, QtGui.QTableWidgetItem(ref))
	bppclient.ui.txhist.setItem(0, 2, QtGui.QTableWidgetItem(frm))
	bppclient.ui.txhist.setItem(0, 3, QtGui.QTableWidgetItem(to))
	bppclient.ui.txhist.setItem(0, 4, QtGui.QTableWidgetItem(format_satoshis(value)))
    bppclient.payhist.commit()
    bppclient.ui.txhist.resizeColumnsToContents()

def loadPayHist():
    try:
	cur = bppclient.payhist.cursor()  
	cur.execute("SELECT * FROM ConfPay")
	bppclient.confpayhist = cur.fetchall()
	cur.execute("SELECT * FROM PendPay")
	bppclient.pendpayhist = {}
	for t in cur.fetchall():
	    bppclient.pendpayhist[t[0]] = (t[1], t[2], t[3], t[4], t[5])
    except Db.Error, e:
        QtGui.QMessageBox.critical(bppclient, 'Error', e.args[0], QtGui.QMessageBox.Ok)
	sys.exit(1)

def cleanPendHist():
    try:
	cur = bppclient.payhist.cursor()  
	cur.execute("SELECT COUNT(*) FROM PendPay")
	nb = cur.next()[0] - 2000
	if nb > 0:
	    cur.execute("SELECT `ROWID` FROM PendPay LIMIT %d"%nb)
	    lr = cur.fetchall()[-1][0]
	    cur.execute("DELETE FROM PendPay WHERE `ROWID` <= %d"%lr)
	    bppclient.payhist.commit()
    except Db.Error, e:
	if bppclient.payhist:
            bppclient.payhist.rollback()
        QtGui.QMessageBox.critical(bppclient, 'Error', e.args[0], QtGui.QMessageBox.Ok)
	sys.exit(1)

def createTables():
    try:
        cur = bppclient.payhist.cursor() 
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS ConfPay(`Txin` TEXT, `Path` TEXT, `From` TEXT, `To` TEXT, `Ref` TEXT, `Ret` TEXT, `Date` TEXT, `Amount` INT);
	    CREATE TABLE IF NOT EXISTS PendPay(`Txin` TEXT, `Path` TEXT, `From` TEXT, `To` TEXT, `Ref` TEXT, `Ret` TEXT);
            """)
        bppclient.payhist.commit()
    except Db.Error, e:
        if bppclient.payhist:
            bppclient.payhist.rollback()
        QtGui.QMessageBox.critical(bppclient, 'Error', e.args[0], QtGui.QMessageBox.Ok)
	sys.exit(1)
    cleanPendHist()

def insertPendPay(v):
    try:
        cur = bppclient.payhist.cursor()
        cur.execute("INSERT INTO PendPay VALUES(?, ?, ?, ?, ?, ?)", v)
        bppclient.payhist.commit()
    except Db.Error, e:
        if bppclient.payhist:
            bppclient.payhist.rollback()
        QtGui.QMessageBox.critical(bppclient, 'Error', e.args[0], QtGui.QMessageBox.Ok)

def start():
    try:
        f = open(os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'bpp_data', 'bppcnx.cfg'),'r')
        c = json.load(f)
        f.close()
        bppclient.cfgmain = c["main"]
        bppclient.cfgbpp = c["bpp"]
        for bppid in bppclient.cfgbpp:
            bppclient.ui.bppidcb.addItem(bppid["bppid"])
        if bppclient.cfgmain["master_pub_key"] != "":
            bppclient.mpkbtc = Btclib.bip32_ckd(bppclient.cfgmain["master_pub_key"], 2)
        if bppclient.cfgmain["priv_seed"] != "":
            bppclient.mpkbpp = Btclib.subkey_for_path(Btclib.bip32_master_key(bppclient.cfgmain["priv_seed"]), "1/1/1")
	    bppclient.wallet.privbtc = Btclib.subkey_for_path(Btclib.bip32_master_key(bppclient.cfgmain["priv_seed"]), "1/1/2")
        if bppclient.cfgmain["keysign"] != "":
            bppclient.keysign = bppclient.cfgmain["keysign"]
        if bppclient.cfgbpp != []:
            bppidcnt()
    except IOError:
        create_mpk()
    updateStatusBar()
    updateReceiveAddrs()

def save_cfg():
    f = open(os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'bpp_data', 'bppcnx.cfg'),'w')
    json.dump({"main" : bppclient.cfgmain, "bpp" : bppclient.cfgbpp}, f)
    f.close()

def create_mpk():
    seed = Btclib.random_electrum_seed()
    mpk = Btclib.subkey_for_path(Btclib.bip32_master_key(seed), "1/1.pub")
    keysign = Btclib.bip32_extract_key(Btclib.subkey_for_path(Btclib.bip32_master_key(seed), "3/3/3/3/1"))
    QtGui.QMessageBox.information(bppclient, 'Welcome', "Your PRIVATE Master Key and your wallet's data have been stored in the \"bpp_data\" folder, please keep it safe!", QtGui.QMessageBox.Ok)
    bppclient.cfgmain = {"priv_seed" : seed, "master_pub_key" : mpk, "keysign" : keysign}
    save_cfg()
    start()

class ElectrumGui:
    def __init__(self, config, network):
	global app, bppclient
    	logging.basicConfig(level=logging.DEBUG,
                            format='%(levelname)-8s %(message)s')
        app = QtGui.QApplication(sys.argv)
        bppclient = BPPClient()
	bppclient.show()
	createTables()
	loadPayHist()

        self.network = network
        self.config = config
        storage = WalletStorage(config)
        set_verbosity(True)

        bppclient.wallet = Wallet(storage)
        bppclient.wallet.start_threads(network)
        
        bppclient.wallet.network.register_callback('updated', self.updated)
        bppclient.wallet.network.register_callback('connected', self.connected)
        #self.wallet.network.register_callback('disconnected', self.disconnected)
        #self.wallet.network.register_callback('disconnecting', self.disconnecting)

	self.connect_timer = QtCore.QTimer()
        self.connect_timer.timeout.connect(self.reconnect)
	self.connect_timer.start(2000)

	bppclient.get_balance = self.get_balance
        start()

    def main(self,url):
        app.exec_()
	if bppclient.bppcnx != None: bppclient.bppcnx.disconnect()
	if bppclient.payhist: bppclient.payhist.close()

    def updated(self):
        s = self.get_balance()
        if s != bppclient.balance:
            invoke_gui(updateStatusBar)
        bppclient.balance = s
	invoke_gui(updateReceiveAddrs)
	invoke_gui(updateHistory)
        return True

    def connected(self):
        invoke_gui(updateStatusBar)

    def reconnect(self):
	if not bppclient.wallet.network.is_connected():
	    self.network.switch_to_random_interface()

    def get_balance(self):
        if bppclient.wallet.network.interface and bppclient.wallet.network.interface.is_connected:
            if not bppclient.wallet.up_to_date:
                msg = _( "Synchronizing..." )
            else: 
                c, u =  bppclient.wallet.get_balance()
                msg = _("Balance")+": %f  "%(Decimal( c ) / 100000000)
                if u: msg += "  [%f unconfirmed]"%(Decimal( u ) / 100000000)
        else:
                msg = _( "Not connected" )
            
        return(msg)




