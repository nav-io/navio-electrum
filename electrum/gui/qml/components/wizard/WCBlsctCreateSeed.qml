import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

WizardComponent {
    securePage: true

    valid: seedtext.text != ''

    function apply() {
        wizard_data['seed'] = seedtext.text
        wizard_data['seed_type'] = 'blsct'
        wizard_data['seed_variant'] = 'bip39'
        wizard_data['seed_extend'] = false
    }

    function setWarningText(numwords) {
        var t = [
            '<p>',
            qsTr('Please save these %1 words on paper (order is important).').arg(numwords),
            qsTr('This seed will allow you to recover your wallet in case of computer failure.'),
            '</p>',
            '<b>' + qsTr('WARNING') + ':</b>',
            '<ul>',
            '<li>' + qsTr('Never disclose your seed.') + '</li>',
            '<li>' + qsTr('Never type it on a website.') + '</li>',
            '<li>' + qsTr('Do not store it electronically.') + '</li>',
            '</ul>'
        ]
        warningtext.text = t.join(' ')
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip:true
        interactive: height < contentHeight

        GridLayout {
            id: mainLayout
            width: parent.width
            columns: 1

            InfoTextArea {
                id: warningtext
                Layout.fillWidth: true
                backgroundColor: constants.darkerDialogBackground
                iconStyle: InfoTextArea.IconStyle.Warn
            }

            Label {
                Layout.topMargin: constants.paddingMedium
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: qsTr('Your wallet generation seed is:')
            }

            SeedTextArea {
                id: seedtext
                readOnly: true
                Layout.fillWidth: true

                BusyIndicator {
                    anchors.centerIn: parent
                    height: parent.height * 2/3
                    visible: seedtext.text == ''
                }
            }

            RowLayout {
                Layout.fillWidth: true

                FlatButton {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    enabled: seedtext.text != ''
                    text: copiedTimer.running ? qsTr('Copied') : qsTr('Copy')
                    icon.source: '../../../icons/copy_bw.png'
                    onClicked: {
                        AppController.textToClipboard(seedtext.text)
                        copiedTimer.restart()
                    }
                }
                FlatButton {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    enabled: seedtext.text != ''
                    text: qsTr('Share')
                    icon.source: '../../../icons/share.png'
                    onClicked: {
                        var dialog = app.genericShareDialog.createObject(app, {
                            title: qsTr('Wallet seed'),
                            text: seedtext.text
                        })
                        dialog.open()
                    }
                }
            }

            Timer {
                id: copiedTimer
                interval: 2000
                repeat: false
            }

            Label {
                Layout.fillWidth: true
                font.pixelSize: constants.fontSizeSmall
                color: constants.mutedForeground
                wrapMode: Text.Wrap
                text: qsTr('The clipboard can be read by other apps. Paper is safer.')
            }

            Component.onCompleted : {
                setWarningText(24)
            }
        }
    }

    Component.onCompleted: {
        bitcoin.generateSeed('blsct')
    }

    Bitcoin {
        id: bitcoin
        onGeneratedSeedChanged: {
            seedtext.text = generatedSeed
            setWarningText(generatedSeed.split(' ').length)
        }
    }
}
