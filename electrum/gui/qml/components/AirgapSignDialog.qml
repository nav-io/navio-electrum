import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Online (watch-only wallet) side of air-gapped signing:
// show the proposal as looping QR fragments, then scan the signed reply
// from the offline device and broadcast it.
ElDialog {
    id: dialog

    required property QtObject request  // AirgapRequest with fragments set
    property string subtitle

    title: qsTr('Sign with offline device')
    iconSource: Qt.resolvedUrl('../../icons/qrcode_white.png')

    width: parent.width
    height: parent.height
    padding: 0

    property bool _scanning: false

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            leftMargin: constants.paddingLarge
            rightMargin: constants.paddingLarge
            contentHeight: contentLayout.height
            clip: true
            interactive: height < contentHeight

            ColumnLayout {
                id: contentLayout
                width: parent.width

                Label {
                    visible: dialog.subtitle
                    Layout.fillWidth: true
                    text: dialog.subtitle
                    wrapMode: Text.Wrap
                    color: Material.accentColor
                }

                // step 1: proposal QR
                ColumnLayout {
                    visible: !dialog._scanning
                    Layout.fillWidth: true

                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        text: qsTr('1. On the offline device, open Wallet menu > Air-gapped signer and scan this code:')
                    }

                    AnimatedQR {
                        Layout.alignment: Qt.AlignHCenter
                        Layout.topMargin: constants.paddingMedium
                        fragments: dialog.request.fragments
                    }
                }

                // step 2: scan reply
                ColumnLayout {
                    visible: dialog._scanning
                    Layout.fillWidth: true

                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        text: qsTr('2. Scan the signed transaction shown on the offline device:')
                    }

                    QRScan {
                        Layout.fillWidth: true
                        Layout.preferredHeight: width
                        continuous: true
                        active: dialog._scanning
                        onFoundText: (data) => {
                            dialog.request.addReplyScan(data)
                        }
                    }

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        visible: dialog.request.replyTotal > 0
                        text: qsTr('Received %1 of %2 parts')
                            .arg(dialog.request.replyReceived)
                            .arg(dialog.request.replyTotal)
                        color: constants.mutedForeground
                    }
                }
            }
        }

        DialogButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                visible: !dialog._scanning
                text: qsTr('Next: scan signed transaction')
                icon.source: '../../icons/confirmed.png'
                onClicked: dialog._scanning = true
            }
            FlatButton {
                Layout.fillWidth: true
                visible: dialog._scanning
                text: qsTr('Back to proposal code')
                icon.source: '../../icons/back.png'
                onClicked: dialog._scanning = false
            }
        }
    }

    Connections {
        target: dialog.request
        function onBroadcastSuccess(txid) {
            var d = app.messageDialog.createObject(app, {
                text: qsTr('Payment sent.') + '\n\n' + qsTr('Reference:') + ' ' + txid
            })
            d.open()
            dialog.close()
        }
        function onBroadcastFailed(message) {
            var d = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            d.open()
        }
    }

    onClosed: destroy()
}
