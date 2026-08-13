import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: root

    property string txid
    property string label
    property string date
    property int confirmations
    property var value  // type: Amount

    property string title: qsTr("Transaction details")

    signal detailsChanged

    padding: 0

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

            GridLayout {
                id: contentLayout
                width: parent.width
                columns: 2

                Label {
                    Layout.columnSpan: 2
                    text: qsTr('Amount')
                    color: Material.accentColor
                }

                FormattedAmount {
                    Layout.columnSpan: 2
                    Layout.leftMargin: constants.paddingLarge
                    amount: root.value
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    text: qsTr('Status')
                    color: Material.accentColor
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.leftMargin: constants.paddingLarge
                    text: root.confirmations > 0
                        ? qsTr('%1 confirmations').arg(root.confirmations)
                        : qsTr('Unconfirmed')
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    visible: root.date
                    text: qsTr('Date')
                    color: Material.accentColor
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.leftMargin: constants.paddingLarge
                    visible: root.date
                    text: root.date
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    visible: root.label
                    text: qsTr('Memo')
                    color: Material.accentColor
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.leftMargin: constants.paddingLarge
                    visible: root.label
                    text: root.label
                    wrapMode: Text.Wrap
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    text: qsTr('Transaction ID')
                    color: Material.accentColor
                }

                RowLayout {
                    Layout.columnSpan: 2
                    Layout.leftMargin: constants.paddingLarge
                    Layout.fillWidth: true

                    Label {
                        Layout.fillWidth: true
                        text: root.txid
                        font.pixelSize: constants.fontSizeMedium
                        font.family: FixedFont
                        wrapMode: Text.WrapAnywhere
                    }
                    ToolButton {
                        icon.source: '../../icons/share.png'
                        icon.color: 'transparent'
                        onClicked: {
                            var dialog = app.genericShareDialog.createObject(app, {
                                title: qsTr('Transaction ID'),
                                text: root.txid
                            })
                            dialog.open()
                        }
                    }
                }
            }
        }
    }
}
