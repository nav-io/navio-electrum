import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "controls"

// Shown when a newer release exists on GitHub: full release notes of every
// version since the one currently running, plus a download shortcut.
ElDialog {
    id: dialog
    title: qsTr('Update available')
    iconSource: Qt.resolvedUrl('../../icons/update.png')

    property string version
    property string changelog

    z: 1
    anchors.centerIn: parent
    padding: 0

    width: parent.width * 5/6
    height: Math.min(parent.height * 3/4, contentLayout.implicitHeight + header.height + constants.paddingXLarge)

    ColumnLayout {
        id: contentLayout
        anchors.fill: parent
        spacing: constants.paddingMedium

        Label {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
            wrapMode: Text.Wrap
            text: qsTr('Navio Electrum %1 is available. Changes since your version:').arg(dialog.version)
        }

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
            contentHeight: changelogLabel.height
            clip: true

            Label {
                id: changelogLabel
                width: parent.width
                wrapMode: Text.Wrap
                textFormat: Text.MarkdownText
                font.pixelSize: constants.fontSizeSmall
                text: dialog.changelog
                onLinkActivated: (link) => Qt.openUrlExternally(link)
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.margins: constants.paddingLarge

            FlatButton {
                Layout.fillWidth: true
                text: qsTr('Later')
                onClicked: dialog.close()
            }
            FlatButton {
                Layout.fillWidth: true
                text: qsTr('Download')
                icon.source: '../../icons/update.png'
                onClicked: {
                    Qt.openUrlExternally('https://github.com/nav-io/navio-electrum/releases/latest')
                    dialog.close()
                }
            }
        }
    }
}
