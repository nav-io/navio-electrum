import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: root
    objectName: 'Tokens'

    property string title: qsTr('Tokens')

    padding: 0

    TokensBackend {
        id: tokens
        wallet: Daemon.currentWallet

        onSendSuccess: (txid) => {
            var dialog = app.messageDialog.createObject(app, {
                text: qsTr('Tokens sent.') + '\n\n' + qsTr('Transaction ID:') + ' ' + txid
            })
            dialog.open()
        }
        onSendFailed: (message) => {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }
        onAuthRequired: (method, authMessage) => {
            app.handleAuthRequired(tokens, method, authMessage)
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.margins: constants.paddingLarge

            contentHeight: contentLayout.height
            clip: true
            interactive: height < contentHeight

            ColumnLayout {
                id: contentLayout
                width: parent.width

                Heading {
                    text: qsTr('Token balances')
                }

                Label {
                    visible: tokens.tokens.length == 0
                    Layout.fillWidth: true
                    color: constants.mutedForeground
                    text: qsTr('No tokens yet. Tokens someone sends to your regular address will show up here.')
                    wrapMode: Text.Wrap
                }

                Repeater {
                    model: tokens.tokens
                    delegate: TextHighlightPane {
                        Layout.fillWidth: true

                        ColumnLayout {
                            width: parent.width
                            RowLayout {
                                Layout.fillWidth: true
                                Label {
                                    Layout.fillWidth: true
                                    font.bold: true
                                    elide: Text.ElideMiddle
                                    text: modelData.name
                                }
                                Label {
                                    font.family: FixedFont
                                    font.bold: true
                                    text: modelData.balance.toLocaleString()
                                }
                            }
                            Label {
                                Layout.fillWidth: true
                                font.pixelSize: constants.fontSizeXSmall
                                font.family: FixedFont
                                color: constants.mutedForeground
                                elide: Text.ElideMiddle
                                text: modelData.token_id
                            }
                            FlatButton {
                                Layout.fillWidth: true
                                visible: !Daemon.currentWallet.isWatchOnly
                                text: qsTr('Send')
                                icon.source: '../../icons/tab_send.png'
                                enabled: !tokens.busy
                                onClicked: {
                                    var dialog = sendTokenDialog.createObject(root, {
                                        tokenId: modelData.token_id,
                                        tokenName: modelData.name,
                                        maxAmount: modelData.balance
                                    })
                                    dialog.open()
                                }
                            }
                        }
                    }
                }

                Heading {
                    Layout.topMargin: constants.paddingLarge
                    text: qsTr('NFTs')
                }

                Label {
                    visible: tokens.nfts.length == 0
                    Layout.fillWidth: true
                    color: constants.mutedForeground
                    text: qsTr('No NFTs yet.')
                    wrapMode: Text.Wrap
                }

                Repeater {
                    model: tokens.nfts
                    delegate: TextHighlightPane {
                        Layout.fillWidth: true

                        ColumnLayout {
                            width: parent.width
                            RowLayout {
                                Layout.fillWidth: true
                                Label {
                                    Layout.fillWidth: true
                                    font.bold: true
                                    elide: Text.ElideMiddle
                                    text: modelData.name + '  #' + modelData.subid
                                }
                            }
                            Label {
                                visible: modelData.memo != ''
                                Layout.fillWidth: true
                                font.pixelSize: constants.fontSizeSmall
                                color: constants.mutedForeground
                                wrapMode: Text.Wrap
                                text: modelData.memo
                            }
                            Label {
                                Layout.fillWidth: true
                                font.pixelSize: constants.fontSizeXSmall
                                font.family: FixedFont
                                color: constants.mutedForeground
                                elide: Text.ElideMiddle
                                text: modelData.token_id
                            }
                            FlatButton {
                                Layout.fillWidth: true
                                visible: !Daemon.currentWallet.isWatchOnly
                                text: qsTr('Send')
                                icon.source: '../../icons/tab_send.png'
                                enabled: !tokens.busy
                                onClicked: {
                                    var dialog = sendTokenDialog.createObject(root, {
                                        tokenId: modelData.token_id,
                                        tokenName: modelData.name + ' #' + modelData.subid,
                                        maxAmount: 1,
                                        isNft: true
                                    })
                                    dialog.open()
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    BusyIndicator {
        anchors.centerIn: parent
        visible: tokens.busy
    }

    Component {
        id: sendTokenDialog
        ElDialog {
            id: _sendTokenDialog

            property string tokenId
            property string tokenName
            property double maxAmount: 0
            property bool isNft: false

            title: qsTr('Send %1').arg(tokenName)
            iconSource: Qt.resolvedUrl('../../icons/tab_send.png')

            anchors.centerIn: parent
            width: parent.width * 0.9
            padding: constants.paddingLarge

            ColumnLayout {
                width: parent.width

                Label {
                    text: qsTr('Recipient')
                    color: Material.accentColor
                }

                ElTextArea {
                    id: sendAddress
                    Layout.fillWidth: true
                    Layout.minimumHeight: 80
                    font.family: FixedFont
                    font.pixelSize: constants.fontSizeSmall
                    wrapMode: TextEdit.WrapAnywhere
                    inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                }

                RowLayout {
                    Layout.fillWidth: true
                    FlatButton {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        text: qsTr('Paste')
                        icon.source: '../../icons/copy_bw.png'
                        onClicked: sendAddress.text = AppController.clipboardToText().trim()
                    }
                    FlatButton {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        text: qsTr('Scan QR')
                        icon.source: '../../icons/qrcode_white.png'
                        onClicked: {
                            var scanner = app.scanDialog.createObject(root, {
                                hint: qsTr('Scan a Navio address')
                            })
                            scanner.onFoundText.connect(function(data) {
                                sendAddress.text = data.trim()
                                scanner.close()
                            })
                            scanner.open()
                        }
                    }
                }

                Label {
                    visible: !_sendTokenDialog.isNft
                    text: qsTr('Amount (max %1)').arg(_sendTokenDialog.maxAmount)
                    color: Material.accentColor
                }

                TextField {
                    id: sendAmount
                    visible: !_sendTokenDialog.isNft
                    Layout.fillWidth: true
                    font.family: FixedFont
                    text: _sendTokenDialog.isNft ? '1' : ''
                    inputMethodHints: Qt.ImhDigitsOnly
                    validator: IntValidator { bottom: 1 }
                }

                FlatButton {
                    Layout.fillWidth: true
                    Layout.topMargin: constants.paddingMedium
                    text: qsTr('Send')
                    icon.source: '../../icons/confirmed.png'
                    enabled: sendAddress.text.trim() != ''
                        && (_sendTokenDialog.isNft || parseInt(sendAmount.text) > 0)
                    onClicked: {
                        var amount = _sendTokenDialog.isNft ? '1' : sendAmount.text
                        tokens.sendToken(_sendTokenDialog.tokenId,
                                         sendAddress.text.trim(), amount, '')
                        _sendTokenDialog.close()
                    }
                }
            }

            onClosed: destroy()
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onBalanceChanged() {
            tokens.updateTokens()
        }
    }
}
