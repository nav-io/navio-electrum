import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root
    securePage: true

    valid: false

    property bool _seedValid: false

    function apply() {
        wizard_data['seed'] = seedtext.text.trim().split(/\s+/).join(' ')
        wizard_data['seed_type'] = 'blsct'
        wizard_data['seed_variant'] = 'bip39'
        wizard_data['seed_extend'] = false
    }

    function checkValid() {
        _seedValid = bitcoin.isBlsctSeed(seedtext.text)
        valid = _seedValid
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
                text: qsTr('Enter your 24-word Navio seed phrase (or 64-character hex seed).')
            }

            SeedTextArea {
                id: seedtext
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingLarge

                allowPaste: true
                placeholderText: qsTr('Enter your seed')

                indicatorValid: root._seedValid
                indicatorText: root._seedValid ? qsTr('Navio seed') : ''
                onTextChanged: {
                    valid = false
                    root._seedValid = false
                    validationTimer.restart()
                }
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
        Qt.callLater(seedtext.forceActiveFocus)
    }
}
