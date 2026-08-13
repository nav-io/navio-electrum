import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import ".."
import "../controls"

WizardComponent {
    securePage: true

    valid: false

    function checkValid() {
        if (skipCheck.checked) {
            valid = true
            return
        }
        var entered = confirm.text.trim().split(/\s+/).join(' ')
        valid = entered == wizard_data['seed']
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip:true
        interactive: height < contentHeight

        ColumnLayout {
            id: mainLayout
            width: parent.width

            InfoTextArea {
                Layout.fillWidth: true
                Layout.bottomMargin: constants.paddingLarge
                backgroundColor: constants.darkerDialogBackground
                text: qsTr('Your seed is important!') + ' ' +
                    qsTr('If you lose your seed, your money will be permanently lost.') + ' ' +
                    qsTr('To make sure that you have properly saved your seed, please retype it here.')
            }

            Label {
                text: qsTr('Confirm your seed (re-enter)')
            }

            SeedTextArea {
                id: confirm
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingSmall
                allowPaste: true
                placeholderText: qsTr('Enter your seed')
                onTextChanged: checkValid()
            }

            ElCheckBox {
                id: skipCheck
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                text: qsTr('Skip verification (I have saved my seed)')
                onCheckedChanged: checkValid()
            }
        }
    }
}
