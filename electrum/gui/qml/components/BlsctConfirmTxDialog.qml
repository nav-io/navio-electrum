import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    required property QtObject finalizer
    required property var satoshis  // type: Amount
    property string address
    property string message

    title: qsTr('Confirm Payment')
    iconSource: Qt.resolvedUrl('../../icons/question.png')

    // copy these to finalizer
    onMessageChanged: finalizer.message = message
    onAddressChanged: finalizer.address = address
    onSatoshisChanged: finalizer.amount = satoshis

    Component.onCompleted: finalizer.doUpdate()

    width: parent.width
    height: parent.height
    padding: 0

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true

            leftMargin: constants.paddingLarge
            rightMargin: constants.paddingLarge

            contentHeight: rootLayout.height
            clip: true
            interactive: height < contentHeight

            GridLayout {
                id: rootLayout
                width: parent.width

                columns: 2

                Label {
                    Layout.columnSpan: 2
                    text: qsTr('Amount to send')
                    color: Material.accentColor
                }

                DialogHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    GridLayout {
                        columns: 2
                        Label {
                            Layout.alignment: Qt.AlignRight
                            font.pixelSize: constants.fontSizeXLarge
                            font.family: FixedFont
                            font.bold: true
                            text: finalizer.valid
                                ? Config.formatSats(finalizer.effectiveAmount, false)
                                : Config.formatSats(dialog.satoshis, false)
                        }

                        Label {
                            Layout.fillWidth: true
                            text: Config.baseUnit
                            color: Material.accentColor
                            font.pixelSize: constants.fontSizeXLarge
                        }

                        Label {
                            Layout.alignment: Qt.AlignRight
                            visible: Daemon.fx.enabled && finalizer.valid
                            font.pixelSize: constants.fontSizeMedium
                            color: constants.mutedForeground
                            text: Daemon.fx.enabled
                                ? Daemon.fx.fiatValue(finalizer.effectiveAmount, false)
                                : ''
                        }

                        Label {
                            Layout.fillWidth: true
                            visible: Daemon.fx.enabled && finalizer.valid
                            text: Daemon.fx.fiatCurrency
                            font.pixelSize: constants.fontSizeMedium
                            color: constants.mutedForeground
                        }
                    }
                }

                Label {
                    Layout.columnSpan: 2
                    text: qsTr('Recipient')
                    color: Material.accentColor
                }

                DialogHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    Label {
                        width: parent.width
                        text: dialog.address
                        font.pixelSize: constants.fontSizeMedium
                        font.family: FixedFont
                        wrapMode: Text.WrapAnywhere
                    }
                }

                Label {
                    Layout.columnSpan: 2
                    text: qsTr('Fee')
                    color: Material.accentColor
                }

                DialogHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    RowLayout {
                        width: parent.width
                        BusyIndicator {
                            visible: finalizer.busy
                            Layout.preferredHeight: constants.iconSizeMedium
                            Layout.preferredWidth: constants.iconSizeMedium
                        }
                        FormattedAmount {
                            visible: finalizer.valid
                            amount: finalizer.fee
                        }
                        Item { Layout.fillWidth: true; implicitHeight: 1 }
                    }
                }

                InfoTextArea {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    Layout.topMargin: constants.paddingLarge
                    Layout.bottomMargin: constants.paddingLarge
                    visible: finalizer.warning != ''
                    text: finalizer.warning
                    iconStyle: InfoTextArea.IconStyle.Warn
                    backgroundColor: constants.darkerDialogBackground
                }
            }
        }

        DialogButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                text: qsTr('Pay...')
                icon.source: '../../icons/confirmed.png'
                enabled: finalizer.valid && !finalizer.busy
                onClicked: doAccept()
            }
        }
    }

    onClosed: doReject()
}
