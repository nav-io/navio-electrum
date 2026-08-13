import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Loops through a list of QR fragment strings (air-gap transfer).
Item {
    id: root

    property var fragments: []
    property int interval: 400
    property int _index: 0

    implicitWidth: qrimg.width
    implicitHeight: qrimg.height + label.height

    onFragmentsChanged: _index = 0

    ColumnLayout {
        anchors.fill: parent
        spacing: constants.paddingSmall

        QRImage {
            id: qrimg
            Layout.alignment: Qt.AlignHCenter
            qrdata: root.fragments.length > 0 ? root.fragments[root._index] : ''
            render: root.fragments.length > 0
        }

        Label {
            id: label
            Layout.alignment: Qt.AlignHCenter
            visible: root.fragments.length > 1
            font.pixelSize: constants.fontSizeSmall
            color: constants.mutedForeground
            text: qsTr('Part %1 of %2 - keep the camera pointed until complete')
                .arg(root._index + 1).arg(root.fragments.length)
        }
    }

    Timer {
        interval: root.interval
        repeat: true
        running: root.visible && root.fragments.length > 1
        onTriggered: root._index = (root._index + 1) % root.fragments.length
    }
}
