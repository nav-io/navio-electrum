import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Offline (full wallet) side of air-gapped signing:
// scan a proposal from the watch-only wallet, verify and confirm it,
// sign, and show the signed transaction as looping QR fragments.
Pane {
    id: root
    objectName: 'AirgapSignerPage'

    property string title: qsTr('Air-gapped signer')

    padding: 0

    // 0 = scanning, 1 = confirm, 2 = show signed
    property int _step: 0

    AirgapSigner {
        id: signer
        wallet: Daemon.currentWallet

        onProposalReady: root._step = 1
        onProposalError: (message) => {
            var d = app.messageDialog.createObject(app, {
                title: qsTr('Invalid proposal'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            d.open()
        }
        onSignedReady: {
            if (signer.replyFragments.length > 0)
                root._step = 2
        }
        onSignFailed: (message) => {
            var d = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            d.open()
        }
        onAuthRequired: (method, authMessage) => {
            app.handleAuthRequired(signer, method, authMessage)
        }
    }

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

                // step 0: scan
                ColumnLayout {
                    visible: root._step == 0
                    Layout.fillWidth: true

                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        text: qsTr('Scan the transaction proposal shown on the online device.')
                    }

                    QRScan {
                        Layout.fillWidth: true
                        Layout.preferredHeight: width
                        continuous: true
                        active: root._step == 0
                        onFoundText: (data) => signer.addScan(data)
                    }

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        visible: signer.total > 0
                        text: qsTr('Received %1 of %2 parts').arg(signer.received).arg(signer.total)
                        color: constants.mutedForeground
                    }
                }

                // step 1: confirm
                ColumnLayout {
                    visible: root._step == 1
                    Layout.fillWidth: true

                    Heading {
                        text: qsTr('Confirm transaction')
                    }

                    InfoTextArea {
                        Layout.fillWidth: true
                        visible: (signer.summary.age_seconds || 0) > 86400
                        iconStyle: InfoTextArea.IconStyle.Warn
                        backgroundColor: constants.darkerDialogBackground
                        text: qsTr('This proposal is more than a day old.')
                    }

                    Repeater {
                        model: signer.summary.outputs || []
                        delegate: TextHighlightPane {
                            Layout.fillWidth: true
                            ColumnLayout {
                                width: parent.width
                                RowLayout {
                                    Layout.fillWidth: true
                                    Label {
                                        Layout.fillWidth: true
                                        font.bold: true
                                        text: modelData.type == 'StakedCommitment'
                                            ? (modelData.delegate_key
                                                ? qsTr('Stake (delegated)')
                                                : qsTr('Stake'))
                                            : modelData.is_mine
                                                ? qsTr('To this wallet')
                                                : qsTr('Payment')
                                    }
                                    Label {
                                        font.family: FixedFont
                                        font.bold: true
                                        text: modelData.token_id
                                            ? modelData.amount.toLocaleString()
                                            : Config.formatSats(modelData.amount, true)
                                    }
                                }
                                Label {
                                    Layout.fillWidth: true
                                    font.pixelSize: constants.fontSizeSmall
                                    font.family: FixedFont
                                    color: constants.mutedForeground
                                    elide: Text.ElideMiddle
                                    text: modelData.address
                                }
                                Label {
                                    visible: modelData.token_id != ''
                                    Layout.fillWidth: true
                                    font.pixelSize: constants.fontSizeXSmall
                                    font.family: FixedFont
                                    color: constants.mutedForeground
                                    elide: Text.ElideMiddle
                                    text: qsTr('Token') + ': ' + modelData.token_id
                                }
                                Label {
                                    visible: modelData.delegate_key != ''
                                    Layout.fillWidth: true
                                    font.pixelSize: constants.fontSizeXSmall
                                    font.family: FixedFont
                                    color: constants.mutedForeground
                                    elide: Text.ElideMiddle
                                    text: qsTr('Delegated to') + ': ' + modelData.delegate_key
                                }
                                Label {
                                    visible: modelData.memo != ''
                                    Layout.fillWidth: true
                                    font.pixelSize: constants.fontSizeSmall
                                    color: constants.mutedForeground
                                    wrapMode: Text.Wrap
                                    text: modelData.memo
                                }
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Label {
                            text: qsTr('Fee') + ':'
                            color: Material.accentColor
                        }
                        Label {
                            font.family: FixedFont
                            text: Config.formatSats(signer.summary.fee || 0, true)
                        }
                    }

                    Label {
                        Layout.fillWidth: true
                        font.pixelSize: constants.fontSizeSmall
                        color: constants.mutedForeground
                        wrapMode: Text.Wrap
                        text: qsTr('Any remaining balance returns to this wallet as change, derived by this device.')
                    }
                }

                // step 2: signed
                ColumnLayout {
                    visible: root._step == 2
                    Layout.fillWidth: true

                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        text: qsTr('Signed. Scan this with the online device to broadcast:')
                    }

                    AnimatedQR {
                        Layout.alignment: Qt.AlignHCenter
                        Layout.topMargin: constants.paddingMedium
                        fragments: signer.replyFragments
                    }
                }
            }
        }

        DialogButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: root._step == 1
                text: qsTr('Reject')
                icon.source: '../../icons/closebutton.png'
                onClicked: {
                    signer.reset()
                    root._step = 0
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: root._step == 1
                enabled: !signer.busy
                text: qsTr('Sign')
                icon.source: '../../icons/confirmed.png'
                onClicked: signer.sign()
            }
            FlatButton {
                Layout.fillWidth: true
                visible: root._step == 2
                text: qsTr('Done')
                icon.source: '../../icons/confirmed.png'
                onClicked: {
                    signer.reset()
                    root._step = 0
                    app.stack.pop()
                }
            }
        }
    }

    BusyIndicator {
        anchors.centerIn: parent
        visible: signer.busy
    }
}
