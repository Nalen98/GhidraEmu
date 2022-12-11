package ghidraemu;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.EventQueue;
import javax.swing.JFrame;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.awt.event.ActionEvent;
import docking.widgets.textfield.IntegerTextField;
import resources.ResourceManager;

public class AddBreakpointPanel {
    private JFrame frame;
    private IntegerTextField AddrTF;
    public AddBreakpointPanel window;
    /**
     * Launch the application.
     */
    public void main() {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    window = new AddBreakpointPanel();
                    window.frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }


    public AddBreakpointPanel() {
        initialize();
    }

    private void initialize() {
        frame = new JFrame();
        frame.setIconImage(ResourceManager.loadImage("images/ico.png").getImage());
        frame.setTitle("Add breakpoint");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setLocationRelativeTo(null);
        frame.setMinimumSize(new Dimension(250, 150));
        AddrTF = new IntegerTextField();
        AddrTF.setHexMode();
        JLabel AddressLb = new JLabel("Address:");
        JButton AddBtn = new JButton("Add");
        AddBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                if (!GhidraEmuProvider.breaks.contains(GhidraEmuProvider.program.getAddressFactory().getAddress(AddrTF.getText()))) {
                    GhidraEmuProvider.breaks.add(GhidraEmuProvider.program.getAddressFactory().getAddress(AddrTF.getText()));
                    BreakpointProvider.breakModel.addRow(new Object[] {
                        BreakpointProvider.breakpointIcon, BigInteger.valueOf(AddrTF.getLongValue())
                    });
                    GhidraEmuPopup.setColor(GhidraEmuProvider.program.getAddressFactory().getAddress(AddrTF.getText()), Color.RED);
                }
                frame.dispose();
            }
        });
        GroupLayout groupLayout = new GroupLayout(frame.getContentPane());
        groupLayout.setHorizontalGroup(
            groupLayout.createParallelGroup(Alignment.TRAILING)
            .addGroup(groupLayout.createSequentialGroup()
                .addGap(59)
                .addComponent(AddBtn, GroupLayout.DEFAULT_SIZE, 152, Short.MAX_VALUE)
                .addGap(70))
            .addGroup(Alignment.LEADING, groupLayout.createSequentialGroup()
                .addGap(30)
                .addComponent(AddressLb, GroupLayout.PREFERRED_SIZE, 75, GroupLayout.PREFERRED_SIZE)
                .addComponent(AddrTF.getComponent(), GroupLayout.DEFAULT_SIZE, 136, Short.MAX_VALUE)
                .addGap(44))
        );
        groupLayout.setVerticalGroup(
            groupLayout.createParallelGroup(Alignment.LEADING)
            .addGroup(groupLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
                    .addComponent(AddressLb)
                    .addComponent(AddrTF.getComponent(), GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(25)
                .addComponent(AddBtn)
                .addContainerGap(50, Short.MAX_VALUE))
        );
        frame.getContentPane().setLayout(groupLayout);
    }
}
