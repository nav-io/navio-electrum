import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: wallettypegroup.checkedButton !== null

    function apply() {
        // apply gets called when the page is rendered and implicitly
        // sets the first radio button or the last selected one when going back
        wizard_data['wallet_type'] = wallettypegroup.checkedButton.wallettype
        wizard_data['seed_type'] = 'blsct'
    }

    ButtonGroup {
        id: wallettypegroup
    }

    ColumnLayout {
        width: parent.width

        RowLayout {
            Layout.fillWidth: true

            Label {
                text: qsTr('Network')
            }

            ComboBox {
                id: networkCombo
                Layout.fillWidth: true
                model: ['mainnet', 'testnet']

                property string _current: AppController.currentChainName()

                Component.onCompleted: {
                    currentIndex = Math.max(0, model.indexOf(_current))
                }

                onActivated: {
                    var selected = model[currentIndex]
                    if (selected == _current)
                        return
                    var dialog = app.messageDialog.createObject(app, {
                        title: qsTr('Switch to %1?').arg(selected),
                        text: [qsTr('Wallets exist per network.'),
                               qsTr('Navio Electrum will close now; reopen it to continue on %1.').arg(selected)].join(' '),
                        yesno: true
                    })
                    dialog.accepted.connect(function() {
                        AppController.setDefaultChain(selected)
                        Qt.quit()
                    })
                    dialog.rejected.connect(function() {
                        networkCombo.currentIndex = networkCombo.model.indexOf(networkCombo._current)
                    })
                    dialog.open()
                }
            }
        }

        Label {
            Layout.fillWidth: true
            text: qsTr('What kind of wallet do you want to create?')
            wrapMode: Text.Wrap
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'blsct'
            checked: true
            text: qsTr('Navio wallet (new seed)')
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'blsct_restore'
            text: qsTr('Restore Navio wallet from seed')
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'blsct_watch'
            text: qsTr('Watch-only wallet (view key)')
        }
    }
}
