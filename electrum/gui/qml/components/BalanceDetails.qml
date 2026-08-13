import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem
    objectName: 'BalanceDetails'

    padding: 0

    ColumnLayout {
        id: rootLayout
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true

            contentHeight: flickableRoot.height
            clip:true
            interactive: height < contentHeight

            Pane {
                id: flickableRoot
                width: parent.width
                padding: constants.paddingLarge

                ColumnLayout {
                    width: parent.width
                    spacing: constants.paddingLarge

                    InfoTextArea {
                        Layout.fillWidth: true
                        Layout.bottomMargin: constants.paddingLarge
                        visible: Daemon.currentWallet.synchronizing || !Network.isConnected
                        text: Daemon.currentWallet.synchronizing
                                  ? qsTr('Your wallet is not synchronized. The displayed balance may be inaccurate.')
                                  : qsTr('Your wallet is not connected to an Electrum server. The displayed balance may be outdated.')
                        iconStyle: InfoTextArea.IconStyle.Warn
                    }

                    Heading {
                        text: qsTr('Wallet balance')
                    }

                    Piechart {
                        id: piechart

                        property real total: 0

                        visible: total > 0
                        Layout.preferredWidth: parent.width
                        implicitHeight: 220 // TODO: sane value dependent on screen
                        innerOffset: 6
                        function updateSlices() {
                            var p = Daemon.currentWallet.getBalancesForPiechart()
                            total = p['total']
                            piechart.slices = [
                                { v: p['confirmed']/total,
                                    color: constants.colorPiechartOnchain, text: qsTr('On-chain') },
                                { v: p['frozen']/total,
                                    color: constants.colorPiechartFrozen, text: qsTr('On-chain (frozen)') },
                                { v: p['unconfirmed']/total,
                                    color: constants.colorPiechartUnconfirmed, text: qsTr('Unconfirmed') },
                                { v: p['unmatured']/total,
                                    color: constants.colorPiechartUnmatured, text: qsTr('Unmatured') },
                            ]
                        }
                    }

                    GridLayout {
                        Layout.alignment: Qt.AlignHCenter
                        visible: Daemon.currentWallet
                        columns: 2

                        RowLayout {
                            Rectangle {
                                Layout.preferredWidth: constants.iconSizeXSmall
                                Layout.preferredHeight: constants.iconSizeXSmall
                                border.color: constants.colorPiechartTotal
                                color: 'transparent'
                                radius: constants.iconSizeXSmall/2
                            }
                            Label {
                                text: qsTr('Total')
                            }
                        }
                        FormattedAmount {
                            amount: Daemon.currentWallet.totalBalance
                        }

                        RowLayout {
                            visible: !Daemon.currentWallet.frozenBalance.isEmpty
                            Rectangle {
                                Layout.preferredWidth: constants.iconSizeXSmall
                                Layout.preferredHeight: constants.iconSizeXSmall
                                color: constants.colorPiechartOnchain
                            }
                            Label {
                                text: qsTr('On-chain')
                            }
                        }
                        FormattedAmount {
                            visible: !Daemon.currentWallet.frozenBalance.isEmpty
                            amount: Daemon.currentWallet.confirmedBalance
                        }

                        RowLayout {
                            visible: !Daemon.currentWallet.frozenBalance.isEmpty
                            Rectangle {
                                Layout.leftMargin: constants.paddingLarge
                                Layout.preferredWidth: constants.iconSizeXSmall
                                Layout.preferredHeight: constants.iconSizeXSmall
                                color: constants.colorPiechartFrozen
                            }
                            Label {
                                text: qsTr('Frozen')
                            }
                        }
                        FormattedAmount {
                            amount: Daemon.currentWallet.frozenBalance
                            visible: !Daemon.currentWallet.frozenBalance.isEmpty
                        }

                        RowLayout {
                            visible: !Daemon.currentWallet.stakedBalance.isEmpty
                            Rectangle {
                                Layout.preferredWidth: constants.iconSizeXSmall
                                Layout.preferredHeight: constants.iconSizeXSmall
                                color: constants.colorPiechartUnmatured
                            }
                            Label {
                                text: qsTr('Staked')
                            }
                        }
                        FormattedAmount {
                            amount: Daemon.currentWallet.stakedBalance
                            visible: !Daemon.currentWallet.stakedBalance.isEmpty
                        }

                        RowLayout {
                            visible: !Daemon.currentWallet.unconfirmedBalance.isEmpty
                            Rectangle {
                                Layout.preferredWidth: constants.iconSizeXSmall
                                Layout.preferredHeight: constants.iconSizeXSmall
                                color: constants.colorPiechartUnconfirmed
                            }
                            Label {
                                text: qsTr('Unconfirmed')
                            }
                        }
                        FormattedAmount {
                            amount: Daemon.currentWallet.unconfirmedBalance
                            visible: !Daemon.currentWallet.unconfirmedBalance.isEmpty
                        }
                    }

                }
            }
        }
    }
    property color navigationBarBackgroundColor: constants.highlightBackground

    Connections {
        target: Daemon.currentWallet
        function onBalanceChanged() {
            piechart.updateSlices()
        }
    }

    Component.onCompleted: {
        piechart.updateSlices()
    }

}
