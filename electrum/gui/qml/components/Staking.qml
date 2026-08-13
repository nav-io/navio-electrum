import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: root
    objectName: 'Staking'

    property string title: qsTr('Staking')

    padding: 0

    StakingBackend {
        id: staking
        wallet: Daemon.currentWallet

        onStakingSuccess: (message, txid) => {
            var dialog = app.messageDialog.createObject(app, {
                text: message + '\n\n' + qsTr('Transaction ID:') + ' ' + txid
            })
            dialog.open()
        }
        onStakingFailed: (message) => {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }
        onAuthRequired: (method, authMessage) => {
            app.handleAuthRequired(staking, method, authMessage)
        }
    }

    AirgapRequest {
        id: airgapRequest
        wallet: Daemon.currentWallet
        onProposalError: (message) => {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }
    }

    Component {
        id: airgapSignDialog
        AirgapSignDialog {}
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        GridLayout {
            Layout.fillWidth: true
            Layout.margins: constants.paddingLarge
            columns: 2

            Label {
                text: qsTr('Staked') + ':'
                color: Material.accentColor
            }
            FormattedAmount {
                amount: staking.stakedBalance
            }
            Label {
                text: qsTr('Available to stake') + ':'
                color: Material.accentColor
            }
            FormattedAmount {
                amount: staking.spendableBalance
            }
            Label {
                text: qsTr('Rewards earned') + ':'
                color: Material.accentColor
            }
            FormattedAmount {
                amount: staking.earnedRewards
            }
        }

        Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            verticalPadding: 0
            horizontalPadding: 0
            background: PaneInsetBackground {}

            ElListView {
                id: listview
                anchors.fill: parent
                clip: true
                model: staking.stakedOutputs

                delegate: ItemDelegate {
                    width: ListView.view.width
                    height: itemLayout.height

                    GridLayout {
                        id: itemLayout
                        columns: 2
                        x: constants.paddingSmall
                        width: parent.width - 2 * constants.paddingSmall

                        Item { Layout.columnSpan: 2; Layout.preferredWidth: 1; Layout.preferredHeight: constants.paddingSmall }

                        Label {
                            font.pixelSize: constants.fontSizeLarge
                            font.family: FixedFont
                            font.bold: true
                            text: Config.formatSats(modelData.amount)
                        }
                        Label {
                            Layout.fillWidth: true
                            horizontalAlignment: Text.AlignRight
                            font.pixelSize: constants.fontSizeSmall
                            color: constants.mutedForeground
                            text: modelData.height > 0
                                ? qsTr('height %1').arg(modelData.height)
                                : qsTr('Unconfirmed')
                        }

                        Label {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            font.pixelSize: constants.fontSizeSmall
                            color: constants.mutedForeground
                            elide: Text.ElideMiddle
                            text: modelData.delegate_key
                                ? qsTr('Delegated to') + ' ' + modelData.delegate_key
                                : qsTr('(not delegated)')
                        }

                        Label {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            visible: modelData.reward_address != ''
                            font.pixelSize: constants.fontSizeSmall
                            color: constants.mutedForeground
                            elide: Text.ElideMiddle
                            text: qsTr('Rewards to') + ' ' + modelData.reward_address
                        }

                        Item { Layout.columnSpan: 2; Layout.preferredWidth: 1; Layout.preferredHeight: constants.paddingSmall }
                    }
                }

                Label {
                    visible: listview.count == 0
                    anchors.centerIn: parent
                    width: parent.width * 4/5
                    font.pixelSize: constants.fontSizeXLarge
                    color: constants.mutedForeground
                    text: qsTr('No staked outputs')
                    wrapMode: Text.Wrap
                    horizontalAlignment: Text.AlignHCenter
                }
            }
        }

        Label {
            Layout.fillWidth: true
            Layout.margins: constants.paddingLarge
            font.pixelSize: constants.fontSizeSmall
            color: constants.mutedForeground
            wrapMode: Text.Wrap
            text: qsTr('Delegated stakes let a staking operator produce blocks with your coins; the operator can never spend or unstake them. Reward routing is honored at the discretion of the operator.')
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Stake...')
                icon.source: '../../icons/tab_send.png'
                enabled: !staking.busy && staking.spendableBalance.satsInt > 0
                onClicked: {
                    var dialog = stakeDialog.createObject(root)
                    dialog.open()
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Unstake...')
                icon.source: '../../icons/tab_receive.png'
                enabled: !staking.busy && staking.unstakeGroups.length > 0
                onClicked: {
                    var dialog = unstakeDialog.createObject(root)
                    dialog.open()
                }
            }
        }
    }

    BusyIndicator {
        anchors.centerIn: parent
        visible: staking.busy
    }

    Component {
        id: stakeDialog
        ElDialog {
            id: _stakeDialog
            title: qsTr('Stake')
            iconSource: Qt.resolvedUrl('../../icons/question.png')

            anchors.centerIn: parent
            width: parent.width * 0.9
            padding: constants.paddingLarge

            ColumnLayout {
                width: parent.width

                Label {
                    text: qsTr('Amount')
                    color: Material.accentColor
                }

                RowLayout {
                    Layout.fillWidth: true
                    BtcField {
                        id: stakeAmount
                        fiatfield: stakeAmountFiat
                        Layout.fillWidth: true
                    }
                    Label {
                        text: Config.baseUnit
                        color: Material.accentColor
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    visible: Daemon.fx.enabled
                    FiatField {
                        id: stakeAmountFiat
                        btcfield: stakeAmount
                        Layout.fillWidth: true
                    }
                    Label {
                        text: Daemon.fx.fiatCurrency
                        color: Material.accentColor
                    }
                }

                Label {
                    Layout.topMargin: constants.paddingSmall
                    text: qsTr('Operator delegation key')
                    color: Material.accentColor
                }

                TextField {
                    id: stakeDelegateKey
                    Layout.fillWidth: true
                    font.family: FixedFont
                    font.pixelSize: constants.fontSizeSmall
                    placeholderText: qsTr('optional; published by the staking operator')
                }

                Label {
                    Layout.topMargin: constants.paddingSmall
                    text: qsTr('Reward address')
                    color: Material.accentColor
                }

                TextField {
                    id: stakeRewardAddress
                    Layout.fillWidth: true
                    font.family: FixedFont
                    font.pixelSize: constants.fontSizeSmall
                    placeholderText: qsTr('optional; defaults to a fresh address of this wallet')
                }

                InfoTextArea {
                    Layout.fillWidth: true
                    Layout.topMargin: constants.paddingMedium
                    compact: true
                    backgroundColor: constants.darkerDialogBackground
                    text: qsTr('Without an operator key the coins are only locked: this wallet does not produce blocks itself. Delegate to a staking operator to have the coins actually stake.')
                }

                FlatButton {
                    Layout.fillWidth: true
                    Layout.topMargin: constants.paddingMedium
                    text: qsTr('Stake')
                    icon.source: '../../icons/confirmed.png'
                    enabled: stakeAmount.textAsSats && stakeAmount.textAsSats.satsInt > 0
                    onClicked: {
                        if (Daemon.currentWallet.isWatchOnly) {
                            airgapRequest.makeStakeProposal(stakeAmount.textAsSats,
                                stakeDelegateKey.text, stakeRewardAddress.text)
                            if (airgapRequest.fragments.length == 0) {
                                _stakeDialog.close()
                                return
                            }
                            var d = airgapSignDialog.createObject(root, {
                                request: airgapRequest,
                                subtitle: qsTr('Stake %1').arg(Config.formatSats(stakeAmount.textAsSats, true))
                            })
                            d.open()
                        } else {
                            staking.stake(stakeAmount.textAsSats, stakeDelegateKey.text, stakeRewardAddress.text)
                        }
                        _stakeDialog.close()
                    }
                }
            }

            onClosed: destroy()
        }
    }

    Component {
        id: unstakeDialog
        ElDialog {
            id: _unstakeDialog
            title: qsTr('Unstake')
            iconSource: Qt.resolvedUrl('../../icons/question.png')

            anchors.centerIn: parent
            width: parent.width * 0.9
            padding: constants.paddingLarge

            ColumnLayout {
                width: parent.width

                Label {
                    text: qsTr('Delegation group')
                    color: Material.accentColor
                }

                ElComboBox {
                    id: unstakeGroup
                    Layout.fillWidth: true
                    model: staking.unstakeGroups
                    displayText: currentIndex < 0 ? '' : groupLabel(staking.unstakeGroups[currentIndex])
                    delegate: ItemDelegate {
                        width: ListView.view.width
                        text: groupLabel(modelData)
                        highlighted: unstakeGroup.highlightedIndex === index
                    }
                    function groupLabel(group) {
                        var label = group.key
                            ? group.key.substring(0, 24) + '...'
                            : qsTr('(not delegated)')
                        return label + '  -  ' + Config.formatSats(group.amount, true)
                    }
                }

                Label {
                    Layout.topMargin: constants.paddingSmall
                    text: qsTr('Amount (empty = all)')
                    color: Material.accentColor
                }

                RowLayout {
                    Layout.fillWidth: true
                    BtcField {
                        id: unstakeAmount
                        fiatfield: unstakeAmountFiat
                        Layout.fillWidth: true
                    }
                    Label {
                        text: Config.baseUnit
                        color: Material.accentColor
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    visible: Daemon.fx.enabled
                    FiatField {
                        id: unstakeAmountFiat
                        btcfield: unstakeAmount
                        Layout.fillWidth: true
                    }
                    Label {
                        text: Daemon.fx.fiatCurrency
                        color: Material.accentColor
                    }
                }

                FlatButton {
                    Layout.fillWidth: true
                    Layout.topMargin: constants.paddingMedium
                    text: qsTr('Unstake')
                    icon.source: '../../icons/confirmed.png'
                    enabled: unstakeGroup.currentIndex >= 0
                    onClicked: {
                        var key = staking.unstakeGroups[unstakeGroup.currentIndex].key
                        var amt = unstakeAmount.textAsSats ? unstakeAmount.textAsSats : Config.unitsToSats('')
                        if (Daemon.currentWallet.isWatchOnly) {
                            airgapRequest.makeUnstakeProposal(amt, key)
                            if (airgapRequest.fragments.length == 0) {
                                _unstakeDialog.close()
                                return
                            }
                            var d = airgapSignDialog.createObject(root, {
                                request: airgapRequest,
                                subtitle: qsTr('Unstake')
                            })
                            d.open()
                        } else {
                            staking.unstake(amt, key)
                        }
                        _unstakeDialog.close()
                    }
                }
            }

            onClosed: destroy()
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onBalanceChanged() {
            staking.updateList()
        }
    }
}
