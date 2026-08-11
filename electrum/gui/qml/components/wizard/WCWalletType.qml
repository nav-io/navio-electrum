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
    }
}
