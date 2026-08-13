import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl
import QtQml

import org.electrum 1.0

import "controls"

Item {
    id: mainView

    property string title: Daemon.currentWallet.name

    property var _sendDialog

    property string _request_amount
    property string _request_description
    property string _request_expiry

    function openInvoice(key) {
        invoice.key = key
        var dialog = invoiceDialog.createObject(app, { invoice: invoice })
        dialog.open()
        return dialog
    }

    function openRequest(key) {
        var dialog = receiveDialog.createObject(app, { key: key })
        dialog.open()
        return dialog
    }

    function openSendDialog() {
        // Qt based send dialog if not on android
        if (!AppController.isAndroid()) {
            _sendDialog = qtSendDialog.createObject(mainView, {invoiceParser: invoiceParser, piResolver: piResolver})
            _sendDialog.open()
            return
        }

        // Android based send dialog if on android
        var scanner = app.scanDialog.createObject(mainView, {
            hint: qsTr('Scan an Invoice or an Address')
        })
        scanner.onFoundText.connect(function(data) {
            data = data.trim()
            if (bitcoin.isRawTx(data)) {
                app.stack.push(Qt.resolvedUrl('TxDetails.qml'), { rawtx: data })
            } else {
                piResolver.recipient = data
            }
            //scanner.destroy()  // TODO
        })
        scanner.open()
    }

    function closeSendDialog() {
        if (!AppController.isAndroid()) {
            if (_sendDialog) {
                _sendDialog.doClose()
                _sendDialog = null
            }
        }
    }

    function restartSendDialog() {
        if (!AppController.isAndroid()) {
            if (_sendDialog) {
                _sendDialog.restart()
            }
            return
        } else {
            openSendDialog()
        }
    }

    function showExport(data, helptext) {
        var dialog = exportTxDialog.createObject(app, {
            text: data[0],
            text_qr: data[1],
            text_help: helptext,
            text_warn: data[2]
                ? ''
                : [qsTr('Warning: Some data (prev txs / "full utxos") was left out of the QR code as it would not fit.'),
                   qsTr('This might cause issues if signing offline.'),
                   qsTr('As a workaround, copy to clipboard or use the Share option instead.')].join(' '),
            tx_label: data[3]
        })
        dialog.open()
    }

    function payOnchain(invoicedialog, invoice) {
        if (Daemon.currentWallet.walletType == 'blsct') {
            payBlsct(invoicedialog, invoice)
            return
        }
        var dialog = confirmPaymentDialog.createObject(mainView, {
                address: invoice.address,
                satoshis: invoice.amountOverride.isEmpty
                    ? invoice.amount
                    : invoice.amountOverride,
                message: invoice.message
        })
        var canComplete = !Daemon.currentWallet.isWatchOnly && Daemon.currentWallet.canSignWithoutCosigner
        dialog.accepted.connect(function() {
            if (invoice.canSave)
                if (!invoice.saveInvoice())
                    return
            if (!canComplete) {
                if (Daemon.currentWallet.isWatchOnly) {
                    dialog.finalizer.saveOrShow()
                } else {
                    dialog.finalizer.sign()
                }
            } else {
                // store txid in invoicedialog so the dialog can detect broadcast success
                invoicedialog.broadcastTxid = dialog.finalizer.finalizedTxid
                dialog.finalizer.signAndSend()
            }
        })
        dialog.open()
    }

    function payBlsct(invoicedialog, invoice) {
        if (Daemon.currentWallet.isWatchOnly) {
            var amount = invoice.amountOverride.isEmpty
                ? invoice.amount
                : invoice.amountOverride
            airgapRequest.makeSendProposal(invoice.address, amount,
                                           invoice.message, amount.isMax)
            if (airgapRequest.fragments.length == 0)
                return
            var agdialog = airgapSignDialog.createObject(mainView, {
                request: airgapRequest,
                subtitle: qsTr('Sending %1 to %2').arg(
                    amount.isMax ? qsTr('all funds') : Config.formatSats(amount, true)
                ).arg(invoice.address)
            })
            var closeInvoice = function(txid) {
                airgapRequest.broadcastSuccess.disconnect(closeInvoice)
                invoicedialog.close()
            }
            airgapRequest.broadcastSuccess.connect(closeInvoice)
            agdialog.open()
            return
        }
        var dialog = blsctConfirmPaymentDialog.createObject(mainView, {
                address: invoice.address,
                satoshis: invoice.amountOverride.isEmpty
                    ? invoice.amount
                    : invoice.amountOverride,
                message: invoice.message
        })
        dialog.accepted.connect(function() {
            if (invoice.canSave)
                if (!invoice.saveInvoice())
                    return
            // store txid in invoicedialog so the dialog can detect broadcast success
            invoicedialog.broadcastTxid = dialog.finalizer.builtTxid
            dialog.finalizer.signAndSend()
        })
        dialog.open()
    }

    function createRequest(lightning, reuse_address) {
        var qamt = Config.unitsToSats(_request_amount)
        Daemon.currentWallet.createRequest(qamt, _request_description, _request_expiry, lightning, reuse_address)
    }

    function startSweep() {
        var dialog = sweepDialog.createObject(app)
        dialog.accepted.connect(function() {
            var finalizerDialog = confirmSweepDialog.createObject(mainView, {
                privateKeys: dialog.privateKeys,
                message: qsTr('Sweep transaction'),
                showOptions: false,
                amountLabelText: qsTr('Total sweep amount'),
                sendButtonText: Daemon.currentWallet.isWatchOnly
                    ? qsTr('Sweep...')
                    : qsTr('Sweep')
            })
            finalizerDialog.accepted.connect(function() {
                if (Daemon.currentWallet.isWatchOnly) {
                    var confirmdialog = app.messageDialog.createObject(mainView, {
                        title: qsTr('Confirm Sweep'),
                        text: qsTr('Current wallet is watch-only. You might not be able to spend from these addresses.\n\nAre you sure?'),
                        yesno: true
                    })
                    confirmdialog.accepted.connect(function() {
                        finalizerDialog.finalizer.send()
                        close()
                    })
                    confirmdialog.open()
                    return
                }
                console.log("Sending sweep transaction")
                finalizerDialog.finalizer.send()
            })
            finalizerDialog.open()
        })
        dialog.open()
    }

    property QtObject menu: Menu {
        id: menu

        parent: Overlay.overlay
        dim: true
        modal: true
        Overlay.modal: Rectangle {
            color: "#44000000"
        }

        property int implicitChildrenWidth: 64
        width: implicitChildrenWidth + 60 + constants.paddingLarge

        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/wallet.png'
            action: Action {
                text: qsTr('Wallet details')
                enabled: app.stack.currentItem.objectName != 'WalletDetails'
                onTriggered: menu.openPage(Qt.resolvedUrl('WalletDetails.qml'))
            }
        }
        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/tab_addresses.png'
            action: Action {
                text: qsTr('Addresses/Coins');
                onTriggered: menu.openPage(Qt.resolvedUrl('Addresses.qml'));
                enabled: app.stack.currentItem.objectName != 'Addresses'
            }
        }
        MenuItem {
            visible: Daemon.currentWallet.walletType == 'blsct'
            height: visible ? implicitHeight : 0
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/tab_coins.png'
            action: Action {
                text: qsTr('Staking')
                enabled: app.stack.currentItem.objectName != 'Staking'
                onTriggered: menu.openPage(Qt.resolvedUrl('Staking.qml'))
            }
        }

        MenuItem {
            visible: Daemon.currentWallet.walletType == 'blsct'
            height: visible ? implicitHeight : 0
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/tab_receive.png'
            action: Action {
                text: qsTr('Tokens')
                enabled: app.stack.currentItem.objectName != 'Tokens'
                onTriggered: menu.openPage(Qt.resolvedUrl('Tokens.qml'))
            }
        }

        MenuItem {
            visible: Daemon.currentWallet.walletType == 'blsct' && !Daemon.currentWallet.isWatchOnly
            height: visible ? implicitHeight : 0
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/qrcode_white.png'
            action: Action {
                text: qsTr('Air-gapped signer')
                enabled: app.stack.currentItem.objectName != 'AirgapSignerPage'
                onTriggered: menu.openPage(Qt.resolvedUrl('AirgapSignerPage.qml'))
            }
        }

        MenuItem {
            visible: Daemon.currentWallet.walletType != 'blsct'
            height: visible ? implicitHeight : 0
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/pen.png'
            action: Action {
                text: Daemon.currentWallet.canSignMessage
                    ? qsTr('Sign/Verify Message')
                    : qsTr('Verify Message')
                onTriggered: {
                    var dialog = app.signVerifyMessageDialog.createObject(app)
                    dialog.open()
                    menu.deselect()
                }
            }
        }

        MenuItem {
            visible: Daemon.currentWallet.walletType != 'blsct'
            height: visible ? implicitHeight : 0
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/sweep.png'
            action: Action {
                text: qsTr('Sweep key(s)')
                onTriggered: {
                    startSweep()
                    menu.deselect()
                }
            }
        }

        MenuSeparator { }

        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/file.png'
            action: Action {
                text: qsTr('Other wallets')
                enabled: app.stack.currentItem.objectName != 'Wallets'
                onTriggered: menu.openPage(Qt.resolvedUrl('Wallets.qml'))
            }
        }

        function openPage(url) {
            stack.pushOnRoot(url)
            deselect()
        }

        function deselect() {
            currentIndex = -1
        }

        // determine widest element and store in implicitChildrenWidth
        function updateImplicitWidth() {
            for (let i = 0; i < menu.count; i++) {
                var item = menu.itemAt(i)
                var txt = item.text
                var txtwidth = fontMetrics.advanceWidth(txt)
                if (txtwidth > menu.implicitChildrenWidth) {
                    menu.implicitChildrenWidth = txtwidth
                }
            }
        }

        FontMetrics {
            id: fontMetrics
            font: menu.font
        }

        Component.onCompleted: updateImplicitWidth()
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        History {
            id: history
            Layout.fillWidth: true
            Layout.fillHeight: true
        }

        ButtonContainer {
            id: buttonContainer
            Layout.fillWidth: true

            FlatButton {
                id: receiveButton
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/tab_receive.png'
                text: qsTr('Receive')
                onClicked: {
                    var dialog = receiveDetailsDialog.createObject(mainView)
                    dialog.open()
                }
                pressAndHoldIndicator: true
                onPressAndHold: {
                    Config.userKnowsPressAndHold = true
                    Daemon.currentWallet.deleteExpiredRequests()
                    app.stack.push(Qt.resolvedUrl('ReceiveRequests.qml'))
                    AppController.haptic()
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/tab_send.png'
                text: qsTr('Send')
                enabled: !invoiceParser.busy && !piResolver.busy && !requestDetails.busy
                onClicked: openSendDialog()
                pressAndHoldIndicator: true
                onPressAndHold: {
                    Config.userKnowsPressAndHold = true
                    app.stack.push(Qt.resolvedUrl('Invoices.qml'))
                    AppController.haptic()
                }
            }
        }
    }
    property color navigationBarBackgroundColor: constants.highlightBackground

    PIResolver {
        id: piResolver
        wallet: Daemon.currentWallet

        onResolveError: (code, message) => {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }

        onInvoiceResolved: (pi) => {
            invoiceParser.fromResolvedPaymentIdentifier(pi)
        }

        onRequestResolved: (pi) => {
            requestDetails.fromResolvedPaymentIdentifier(pi)
        }
    }

    RequestDetails {
        id: requestDetails
        wallet: Daemon.currentWallet
    }

    Invoice {
        id: invoice
        wallet: Daemon.currentWallet
    }

    InvoiceParser {
        id: invoiceParser
        wallet: Daemon.currentWallet
        onValidationError: (code, message) => {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.closed.connect(function() {
                restartSendDialog()
            })
            dialog.open()
        }
        onValidationWarning: (code, message) => {
            if (code == 'no_channels') {
                var dialog = app.messageDialog.createObject(app, {
                    text: message
                })
                dialog.closed.connect(function() {
                    restartSendDialog()
                })
                dialog.open()
                // TODO: ask user to open a channel, if funds allow
                // and maybe store invoice if expiry allows
            }
        }
        onValidationSuccess: {
            closeSendDialog()
            var dialog = invoiceDialog.createObject(app, {
                invoice: invoiceParser
            })
            dialog.open()
        }
        onInvoiceCreateError: (code, message) => {
            var msg = qsTr('Cannot save invoice') + ': ' + message
            var dialog = app.messageDialog.createObject(app, {
                text: msg
            })
            dialog.open()
        }
    }

    Bitcoin {
        id: bitcoin
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            if (!Daemon.currentWallet) {  // wallet got deleted
                app.stack.replaceRoot('Wallets.qml')
                return
            }
            infobanner.hide() // start hidden when switching wallets
        }
    }

    Connections {
        target: app
        function onPendingIntentChanged() {
            if (app.pendingIntent) {
                piResolver.recipient = app.pendingIntent
                app.pendingIntent = ""
            }
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onRequestCreateSuccess(key) {
            openRequest(key)
        }
        function onRequestCreateError(error) {
            console.log(error)
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: error
            })
            dialog.open()
        }
        function onOtpRequested() {
            console.log('OTP requested')
            var dialog = otpDialog.createObject(mainView)
            dialog.open()
        }
        function onBroadcastFailed(txid, code, message) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }
        function onPaymentFailed(invoice_id, message) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message ? message : qsTr('Payment failed')
            })
            dialog.open()
        }
    }

    Component {
        id: invoiceDialog
        InvoiceDialog {
            id: _invoiceDialog

            width: parent.width
            height: parent.height

            onDoPay: {
                if (invoice.invoiceType == Invoice.OnchainInvoice) {
                    payOnchain(_invoiceDialog, invoice)
                }
            }

            onClosed: destroy()

            Connections {
                target: Daemon.currentWallet
                function onSaveTxSuccess(txid) {
                    _invoiceDialog.close()
                }
            }
        }
    }

    Component {
        id: qtSendDialog
        SendDialog {
            width: parent.width
            height: parent.height

            onTxFound: (data) => {
                app.stack.push(Qt.resolvedUrl('TxDetails.qml'), { rawtx: data })
                close()
            }
            onClosed: destroy()
        }
    }

    Component {
        id: receiveDetailsDialog

        ReceiveDetailsDialog {
            id: _receiveDetailsDialog
            width: parent.width * 0.9
            anchors.centerIn: parent
            onAccepted: {
                console.log('accepted')
                _request_amount = _receiveDetailsDialog.amount
                _request_description = _receiveDetailsDialog.description
                _request_expiry = _receiveDetailsDialog.expiry
                createRequest(false, false)
            }
            onRejected: {
                console.log('rejected')
            }
            onClosed: destroy()
        }
    }

    Component {
        id: receiveDialog
        ReceiveDialog {
            width: parent.width
            height: parent.height

            onRequestPaid: {
                close()
                var capturedHistoryModel = Daemon.currentWallet.historyModel
                if (Daemon.currentWallet.walletType != 'blsct') {
                    let paidTxid = getPaidTxid()
                    var page = app.stack.push(Qt.resolvedUrl('TxDetails.qml'), {'txid': paidTxid})
                    page.detailsChanged.connect(function() {
                            capturedHistoryModel.updateTxLabel(paidTxid, page.label)
                        }
                    )
                }
            }
            onClosed: destroy()
        }
    }

    Component {
        id: confirmPaymentDialog
        ConfirmTxDialog {
            id: _confirmPaymentDialog
            title: qsTr('Confirm Payment')
            finalizer: TxFinalizer {
                wallet: Daemon.currentWallet
                canRbf: true
                onFinished: (signed, saved, complete) => {
                    if (!complete) {
                        var msg
                        if (wallet.isWatchOnly) {
                            // tx created in watchonly wallet. Show QR for signer(s)
                            if (wallet.isMultisig) {
                                msg = qsTr('Transaction created. Present this QR code to one of the co-cigners or signing devices')
                            } else {
                                msg = qsTr('Transaction created. Present this QR code to the signing device')
                            }
                        } else {
                            if (signed) {
                                msg = qsTr('Transaction created and partially signed by this wallet. Present this QR code to the next co-signer')
                            } else {
                                msg = qsTr('Transaction created but not signed by this wallet yet. Sign the transaction and present this QR code to the next co-signer')
                            }
                        }
                        showExport(getSerializedTx(), msg)
                    }
                    _confirmPaymentDialog.destroy()
                }
                onSignError: (message) => {
                    var dialog = app.messageDialog.createObject(mainView, {
                        title: qsTr('Error'),
                        text: [qsTr('Could not sign tx'), message].join('\n\n'),
                        iconSource: '../../../icons/warning.png'
                    })
                    dialog.open()
                }
            }

            // TODO: lingering confirmPaymentDialogs can raise exceptions in
            // the child finalizer when currentWallet disappears, but we need
            // it long enough for the finalizer to finish..
            // onClosed: destroy()
        }
    }

    AirgapRequest {
        id: airgapRequest
        wallet: Daemon.currentWallet
        onProposalError: (message) => {
            var dialog = app.messageDialog.createObject(mainView, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }
    }

    Component {
        id: airgapSignDialog
        AirgapSignDialog {}
    }

    Component {
        id: blsctConfirmPaymentDialog
        BlsctConfirmTxDialog {
            id: _blsctConfirmPaymentDialog
            finalizer: BlsctFinalizer {
                wallet: Daemon.currentWallet
                onFinished: (txid) => {
                    _blsctConfirmPaymentDialog.destroy()
                }
                onSendFailed: (message) => {
                    var dialog = app.messageDialog.createObject(mainView, {
                        title: qsTr('Error'),
                        text: [qsTr('Could not send tx'), message].join('\n\n'),
                        iconSource: '../../../icons/warning.png'
                    })
                    dialog.open()
                }
                onAuthRequired: (method, authMessage) => {
                    app.handleAuthRequired(_blsctConfirmPaymentDialog.finalizer, method, authMessage)
                }
            }
        }
    }

    Component {
        id: confirmSweepDialog
        ConfirmTxDialog {
            id: _confirmSweepDialog

            property string privateKeys
            title: qsTr('Confirm Sweep')
            satoshis: MAX
            finalizer: SweepFinalizer {
                wallet: Daemon.currentWallet
                canRbf: true
                privateKeys: _confirmSweepDialog.privateKeys
            }
        }
    }

    Component {
        id: otpDialog
        OtpDialog {
            width: parent.width * 2/3
            anchors.centerIn: parent

            onClosed: destroy()
        }
    }

    Component {
        id: exportTxDialog
        ExportTxDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: sweepDialog
        SweepDialog {
            onClosed: destroy()
        }
    }

    Component.onCompleted: {
        console.log("WalletMainView completed: ", Daemon.currentWallet.name)
        if (app.pendingIntent) {
            piResolver.recipient = app.pendingIntent
            app.pendingIntent = ""
        }
    }
}

