import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root
    securePage: true

    valid: false

    property bool _keyValid: false

    function apply() {
        wizard_data['seed'] = viewkeytext.text.trim()
        wizard_data['seed_type'] = 'blsct'
        wizard_data['seed_variant'] = 'bip39'
        wizard_data['seed_extend'] = false
        wizard_data['creation_date'] = creationdate.text.trim()
    }

    function checkValid() {
        _keyValid = bitcoin.isBlsctViewKey(viewkeytext.text)
        valid = _keyValid
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip:true
        interactive: height < contentHeight

        ColumnLayout {
            id: mainLayout
            width: parent.width

            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: qsTr('Enter the view key string of the wallet to watch (shown under Wallet details > View key in the wallet that owns the funds).')
            }

            ElTextArea {
                id: viewkeytext
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingLarge
                Layout.minimumHeight: 160
                font.family: FixedFont
                font.pixelSize: constants.fontSizeSmall
                wrapMode: TextEdit.WrapAnywhere
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                onTextChanged: {
                    valid = false
                    root._keyValid = false
                    validationTimer.restart()
                }
            }

            Label {
                Layout.fillWidth: true
                visible: viewkeytext.text != ''
                color: root._keyValid ? 'green' : 'red'
                text: root._keyValid ? qsTr('Valid view key') : qsTr('Not a valid view key')
            }

            RowLayout {
                Layout.fillWidth: true

                FlatButton {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    text: qsTr('Paste')
                    icon.source: '../../../icons/copy_bw.png'
                    onClicked: {
                        viewkeytext.text = AppController.clipboardToText().trim()
                    }
                }
                FlatButton {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    text: qsTr('Scan QR')
                    icon.source: '../../../icons/qrcode_white.png'
                    onClicked: {
                        var scanner = app.scanDialog.createObject(root, {
                            hint: qsTr('Scan the view key QR code')
                        })
                        scanner.onFoundText.connect(function(data) {
                            viewkeytext.text = data.trim()
                            scanner.close()
                        })
                        scanner.open()
                    }
                }
            }

            Label {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                wrapMode: Text.Wrap
                font.pixelSize: constants.fontSizeSmall
                color: constants.mutedForeground
                text: qsTr('Wallet creation date (optional). Skips scanning blocks older than this, making the restore much faster.')
            }

            TextField {
                id: creationdate
                Layout.fillWidth: true
                font.family: FixedFont
                placeholderText: qsTr('YYYY-MM-DD')
                inputMethodHints: Qt.ImhPreferNumbers | Qt.ImhNoPredictiveText
            }

            InfoTextArea {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                compact: true
                backgroundColor: constants.darkerDialogBackground
                text: qsTr('A watch-only wallet sees incoming coins, balances and history, but cannot spend or stake.')
            }
        }
    }

    Timer {
        id: validationTimer
        interval: 500
        repeat: false
        onTriggered: checkValid()
    }

    Bitcoin {
        id: bitcoin
    }

    Component.onCompleted: {
        Qt.callLater(viewkeytext.forceActiveFocus)
    }
}
