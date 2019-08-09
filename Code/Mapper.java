/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;


public class Mapper {
    static String CONNECTION_CLOSED = "ConnectionClosed";
    static String RESET = "RESET";
    int listenPort = 8888;
    int targetPort = 4433;
    int timeout = 100;
    String targetHostname = "localhost";

    Config config;
    State state;
    TlsContext context;

    public Mapper() {
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
        Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.OFF);
    }

    public void initialise() {
        config = Config.createConfig();
        config.setEnforceSettings(false);

        OutboundConnection clientConnection = new OutboundConnection(targetPort, targetHostname);
        clientConnection.setTimeout(timeout);
        config.setDefaultClientConnection(clientConnection);

        setupConfig();

        try {
            initialiseSession();
        } catch (Exception e) {
            System.out.println("Session could not be initialized due to the following exception:\n" + e.getMessage());
        }
    }

    // Set up all desired configurations
    public void setupConfig() {
        // Configurations for protocol version (TLS 1.3 Draft 21)
        List<ProtocolVersion> versions = new LinkedList<>();
        versions.add(ProtocolVersion.TLS13_DRAFT21);
        config.setSupportedVersions(versions);
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setDefaultHighestClientProtocolVersion(ProtocolVersion.TLS13_DRAFT21);
        config.setDefaultLastRecordProtocolVersion(ProtocolVersion.TLS13_DRAFT21);

        // Configurations for signature algorithms
        List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = new LinkedList<>();
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm
                .getSignatureAndHashAlgorithm(new byte[] { 0x04, 0x01 }));
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm
                .getSignatureAndHashAlgorithm(new byte[] { 0x04, 0x03 }));
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm
                .getSignatureAndHashAlgorithm(new byte[] { 0x08, 0x04 }));
        config.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);

        // Configurations for cipher suites
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        cipherSuites.add(CipherSuite.TLS_AES_128_CCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_AES_128_CCM_8_SHA256);
        config.setDefaultClientSupportedCiphersuites(cipherSuites);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setDefaultServerSupportedCiphersuites(cipherSuites);

        // configurations for key share and supported groups
        config.setNamedCurves(NamedCurve.ECDH_X25519);
        config.setKeyShareType(NamedCurve.ECDH_X25519);
        config.setKeySharePublic(hexStringToByteArray("2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"));
        config.setKeySharePrivate(hexStringToByteArray("03bd8bca70c19f657e897e366dbe21a466e4924af6082dbdf573827bcdde5def"));

        // Some default configurations and the actual key share
        config.setDefaultServerHandshakeTrafficSecret(new byte[] { 0x00 });
        config.setDefaultClientHandshakeTrafficSecret(new byte[] { 0x00 });
        config.setDefaultServerApplicationTrafficSecret(new byte[] { 0x00 });
        config.setDefaultClientApplicationTrafficSecret(new byte[] { 0x00 });
        config.setDefaultPreMasterSecret(new byte[] { 0x00 });
        config.setDefaultMasterSecret(hexStringToByteArray("04010501060104030503060308040805"));
        config.setDefaultClientRandom(hexStringToByteArray("929ea06a60b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c"));

        // extensions
        config.setAddSupportedVersionsExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgrorithmsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setUseRandomUnixTime(true);
        config.setAddECPointFormatExtension(false);
        config.setAddRenegotiationInfoExtension(false);
    }

    public void initialiseSession() throws IOException {
        WorkflowTrace trace = new WorkflowTrace();
        state = new State(config, trace);
        context = state.getTlsContext();

        ConnectorTransportHandler transportHandler = new ConnectorTransportHandler(config.getDefaultClientConnection()
                .getTimeout(), config.getDefaultClientConnection().getHostname(), config.getDefaultClientConnection()
                .getPort());
        context.setTransportHandler(transportHandler);
        context.initTransportHandler();
        context.initRecordLayer();
    }

    public void reset() throws IOException {
        close();
        initialiseSession();
    }

    public void close() throws IOException {
        state.getTlsContext().getTransportHandler().closeConnection();
    }

    public void sendMessage(ProtocolMessage message) {
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(message);
        SendAction action = new SendAction(messages);
        action.normalize();
        action.execute(state);
    }

    public String receiveMessages() throws IOException {
        String outputMessage;

        // First check if the socket is still open
        if (state.getTlsContext().getTransportHandler().isClosed())
            return CONNECTION_CLOSED;

        List<String> receivedMessages = new LinkedList<>();
        ReceiveAction action = new ReceiveAction(new LinkedList<>());
        action.normalize();
        // Perform the actual receiving of the message
        action.execute(state);

        // Iterate over all received messages and build a string containing
        // their respective types
        for (ProtocolMessage message : action.getReceivedMessages()) {
            System.out.println(niceFormat(message.getCompleteResultingMessage().getOriginalValue(),
                    message.toCompactString(), 16));

            if (message.getProtocolMessageType() == ProtocolMessageType.ALERT) {
                AlertMessage alert = (AlertMessage) message;
                AlertLevel level = AlertLevel.getAlertLevel(alert.getLevel().getValue());
                AlertDescription description = AlertDescription.getAlertDescription(alert.getDescription().getValue());
                outputMessage = "ALERT_" + level.name() + "_";
                if (description == null)
                    outputMessage += "UNKNOWN";
                else
                    outputMessage += description.name();

            } else
                outputMessage = message.toCompactString();

            receivedMessages.add(outputMessage);
        }

        if (state.getTlsContext().getTransportHandler().isClosed())
            receivedMessages.add(CONNECTION_CLOSED);

        if (receivedMessages.size() > 0)
            return String.join("|", receivedMessages);
        else
            return "-";
    }

    public String processInput(String inputSymbol) throws Exception {
        // Upon receiving the special input symbol RESET, we reset the system
        if (inputSymbol.equals(RESET)) {
            reset();
            return "";
        }

        // Check if the socket is already closed, in which case we don't have to bother trying to send data out
        if (state.getTlsContext().getTransportHandler().isClosed())
            return CONNECTION_CLOSED;

        // Process the regular input symbols for the state machine
        switch (inputSymbol) {
            case "ClientHello":
                sendMessage(new ClientHelloMessage(config));
                break;
            case "ServerHello":
                sendMessage(new ServerHelloMessage(config));
                break;
            case "HelloRetryRequest":
                sendMessage(new HelloRetryRequestMessage(config));
                break;
            case "EncryptedExtensions":
                sendMessage(new EncryptedExtensionsMessage(config));
                break;
            case "Certificate":
                sendMessage(new CertificateMessage(config));
                break;
            case "CertificateRequest":
                sendMessage(new CertificateRequestMessage(config));
                break;
            case "CertificateVerify":
                sendMessage(new CertificateVerifyMessage(config));
                break;
            case "Finished":
                sendMessage(new FinishedMessage(config));
                break;
            case "NewSessionTicket":
                sendMessage(new NewSessionTicketMessage());
                break;
            case "EndOfEarlyData":
                sendMessage(new EndOfEarlyDataMessage());
                break;
            case "ApplicationData":
                ApplicationMessage am = new ApplicationMessage();
                ModifiableByteArray data = new ModifiableByteArray();
                data.setModification(ByteArrayModificationFactory.explicitValue("GET / HTTP/1.0\n".getBytes()));
                am.setData(data);
                sendMessage(am);
                break;

            default:
                throw new Exception("Unknown input symbol: " + inputSymbol);
        }

        return receiveMessages();
    }

    public void startListening() throws Exception {
        ServerSocket serverSocket = new ServerSocket(listenPort);
        System.out.println("Listening on port " + listenPort);

        Socket clientSocket = serverSocket.accept();
        clientSocket.setTcpNoDelay(true);

        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        String input, output;

        while ((input = in.readLine()) != null) {
            output = processInput(input);
            System.out.println(input + " / " + output);
            out.println(output);
            out.flush();
        }

        clientSocket.close();
        serverSocket.close();
    }


    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));

        return data;
    }

    // Not important, just handy for debugging purposes
    public String niceFormat(byte[] message, String name, int lineWidth) {
        StringBuilder sb = new StringBuilder();

        for (byte b : message)
            sb.append(String.format("%02X ", b));

        String[] chunks = sb.toString().split(" ");
        StringBuilder new_sb = new StringBuilder(name + " [Length: " + chunks.length + "]\n");

        for (int i = 0; i < chunks.length; i++)
            if (i == 0 || i % lineWidth != 0)
                new_sb.append(chunks[i] + " ");
            else
                new_sb.append("\n" + chunks[i] + " ");

        return new_sb.append("\n").toString();
    }

    public static void main(String args[]) {
        try {
            Mapper mapper = new Mapper();
            mapper.initialise();
            mapper.startListening();


        } catch (Exception e) {
            System.err.println("Error occurred: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}
