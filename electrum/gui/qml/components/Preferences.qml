import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: preferences
    objectName: 'Properties'

    property string title: qsTr("Preferences")

    padding: 0

    property var _baseunits: ['NAV','mNAV','bits','sat']

    ColumnLayout {
        anchors.fill: parent

        Flickable {
            Layout.fillHeight: true
            Layout.fillWidth: true

            contentHeight: prefsPane.height
            interactive: height < contentHeight
            clip: true

            Pane {
                id: prefsPane
                width: parent.width

                GridLayout {
                    columns: 2
                    width: parent.width

                    PrefsHeading {
                        Layout.columnSpan: 2
                        text: qsTr('Network')
                    }

                    Label {
                        text: qsTr('Chain')
                    }

                    ElComboBox {
                        id: networkCombo
                        model: ['mainnet', 'testnet']

                        property string _current: AppController.currentChainName()

                        Component.onCompleted: {
                            currentIndex = Math.max(0, model.indexOf(_current))
                        }

                        onActivated: {
                            var selected = model[currentIndex]
                            if (selected == networkCombo._current)
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

                    PrefsHeading {
                        Layout.columnSpan: 2
                        text: qsTr('User Interface')
                    }

                    Label {
                        text: qsTr('Language')
                    }

                    ElComboBox {
                        id: language
                        textRole: 'text'
                        valueRole: 'value'
                        model: Config.languagesAvailable
                        onCurrentValueChanged: {
                            if (activeFocus) {
                                if (Config.language != currentValue) {
                                    Config.language = currentValue
                                    var dialog = app.messageDialog.createObject(app, {
                                        text: qsTr('Please restart Electrum to activate the new GUI settings')
                                    })
                                    dialog.open()
                                }
                            }
                        }
                    }

                    Label {
                        text: qsTr('Base unit')
                    }

                    ElComboBox {
                        id: baseUnit
                        model: _baseunits
                        onCurrentValueChanged: {
                            if (activeFocus)
                                Config.baseUnit = currentValue
                        }
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        spacing: 0
                        Switch {
                            id: thousands
                            onCheckedChanged: {
                                if (activeFocus)
                                    Config.thousandsSeparator = checked
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Add thousands separators to amounts')
                            wrapMode: Text.Wrap
                        }
                    }

                    RowLayout {
                        spacing: 0
                        Switch {
                            id: fiatEnable
                            onCheckedChanged: {
                                if (activeFocus)
                                    Daemon.fx.enabled = checked
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Fiat Currency')
                            wrapMode: Text.Wrap
                        }
                    }

                    ElComboBox {
                        id: currencies
                        model: Daemon.fx.currencies
                        enabled: Daemon.fx.enabled
                        onCurrentValueChanged: {
                            if (activeFocus)
                                Daemon.fx.fiatCurrency = currentValue
                        }
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        spacing: 0
                        Switch {
                            id: historicRates
                            enabled: Daemon.fx.enabled
                            onCheckedChanged: {
                                if (activeFocus)
                                    Daemon.fx.historicRates = checked
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Historic rates')
                            wrapMode: Text.Wrap
                        }
                    }

                    Label {
                        text: qsTr('Exchange rate provider')
                        enabled: Daemon.fx.enabled
                    }

                    ElComboBox {
                        id: rateSources
                        enabled: Daemon.fx.enabled
                        model: Daemon.fx.rateSources
                        onModelChanged: {
                            currentIndex = rateSources.indexOfValue(Daemon.fx.rateSource)
                        }
                        onCurrentValueChanged: {
                            if (activeFocus)
                                Daemon.fx.rateSource = currentValue
                        }
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        spacing: 0
                        Switch {
                            id: syncLabels
                            onCheckedChanged: {
                                if (activeFocus)
                                    AppController.setPluginEnabled('labels', checked)
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Synchronize labels')
                            wrapMode: Text.Wrap
                        }
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        spacing: 0
                        Switch {
                            id: psbtNostr
                            onCheckedChanged: {
                                if (activeFocus)
                                    AppController.setPluginEnabled('psbt_nostr', checked)
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Nostr Cosigner')
                            wrapMode: Text.Wrap
                        }
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        spacing: 0
                        enabled: AppController.isAndroid()
                        Switch {
                            id: setMaxBrightnessOnQrDisplay
                            onCheckedChanged: {
                                if (activeFocus)
                                    Config.setMaxBrightnessOnQrDisplay = checked
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Increase brightness when displaying QR codes')
                            wrapMode: Text.Wrap
                        }
                    }

                    PrefsHeading {
                        Layout.columnSpan: 2
                        text: qsTr('Security')
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        spacing: 0

                        property bool noWalletPassword: Daemon.currentWallet ? Daemon.currentWallet.verifyPassword('') : true
                        enabled: Daemon.currentWallet && !noWalletPassword

                        Switch {
                            id: paymentAuthentication
                            // showing the toggle as checked even if the wallet has no password would be misleading
                            checked: Config.paymentAuthentication && !(Daemon.currentWallet && parent.noWalletPassword)
                            onCheckedChanged: {
                                if (activeFocus) {
                                    // will request authentication when checked = false
                                    console.log('paymentAuthentication: ' + checked)
                                    Config.paymentAuthentication = checked;
                                }
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Request authentication for payments')
                            wrapMode: Text.Wrap
                        }
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        spacing: 0
                        // isAvailable checks phone support and if a fingerprint is enrolled on the system
                        enabled: Biometrics.isAvailable && Daemon.currentWallet

                        Connections {
                            target: Biometrics
                            function onEnablingFailed(error) {
                                if (error === 'CANCELLED') {
                                    return // don't show error popup
                                }
                                var err = app.messageDialog.createObject(app, {
                                    text: qsTr('Failed to enable biometric authentication: ') + error
                                })
                                err.open()
                            }
                        }

                        Switch {
                            id: useBiometrics
                            checked: Biometrics.isEnabled
                            onCheckedChanged: {
                                if (activeFocus) {
                                    useBiometrics.focus = false
                                    if (checked) {
                                        if (Daemon.singlePasswordEnabled) {
                                            Biometrics.enable(Daemon.singlePassword)
                                        } else {
                                            useBiometrics.checked = false
                                            var err = app.messageDialog.createObject(app, {
                                                title: qsTr('Unavailable'),
                                                text: [
                                                    qsTr("Cannot activate biometric authentication because you have wallets with different passwords."),
                                                    qsTr("To use biometric authentication you first need to change all wallet passwords to the same password.")
                                                ].join("\n")
                                            })
                                            err.open()
                                        }
                                    } else {
                                        Biometrics.disableProtected()
                                    }
                                }
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Biometric authentication')
                            wrapMode: Text.Wrap
                        }
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        spacing: 0
                        enabled: AppController.isAndroid()
                        Switch {
                            id: disableScreenshots
                            onCheckedChanged: {
                                if (activeFocus)
                                    Config.alwaysAllowScreenshots = !checked
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Protect secrets from screenshots')
                            wrapMode: Text.Wrap
                        }
                    }

                    PrefsHeading {
                        Layout.columnSpan: 2
                        text: qsTr('Wallet behavior')
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        spacing: 0
                        Switch {
                            id: spendUnconfirmed
                            onCheckedChanged: {
                                if (activeFocus)
                                    Config.spendUnconfirmed = checked
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Spend unconfirmed')
                            wrapMode: Text.Wrap
                        }
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        spacing: 0
                        Switch {
                            id: freezeReusedAddressUtxos
                            onCheckedChanged: {
                                if (activeFocus)
                                    Config.freezeReusedAddressUtxos = checked
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: Config.shortDescFor('WALLET_FREEZE_REUSED_ADDRESS_UTXOS')
                            wrapMode: Text.Wrap
                        }
                    }

                    PrefsHeading {
                        Layout.columnSpan: 2
                        text: qsTr('Advanced')
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        spacing: 0
                        Switch {
                            id: enableDebugLogs
                            onCheckedChanged: {
                                if (activeFocus)
                                    Config.enableDebugLogs = checked
                            }
                            enabled: Config.canToggleDebugLogs
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Enable debug logs (for developers)')
                            wrapMode: Text.Wrap
                        }
                    }
                }
            }
        }
    }

    Component.onCompleted: {
        language.currentIndex = language.indexOfValue(Config.language)
        baseUnit.currentIndex = _baseunits.indexOf(Config.baseUnit)
        thousands.checked = Config.thousandsSeparator
        currencies.currentIndex = currencies.indexOfValue(Daemon.fx.fiatCurrency)
        historicRates.checked = Daemon.fx.historicRates
        rateSources.currentIndex = rateSources.indexOfValue(Daemon.fx.rateSource)
        fiatEnable.checked = Daemon.fx.enabled
        spendUnconfirmed.checked = Config.spendUnconfirmed
        freezeReusedAddressUtxos.checked = Config.freezeReusedAddressUtxos
        enableDebugLogs.checked = Config.enableDebugLogs
        disableScreenshots.checked = !Config.alwaysAllowScreenshots && AppController.isAndroid()
        setMaxBrightnessOnQrDisplay.checked = Config.setMaxBrightnessOnQrDisplay && AppController.isAndroid()
        syncLabels.checked = AppController.isPluginEnabled('labels')
        psbtNostr.checked = AppController.isPluginEnabled('psbt_nostr')
    }
}
