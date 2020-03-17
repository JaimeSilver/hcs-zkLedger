package net.aochain.hcs;

import com.hedera.hashgraph.sdk.Client;
import com.hedera.hashgraph.sdk.HederaStatusException;
import com.hedera.hashgraph.sdk.TransactionId;
import com.hedera.hashgraph.sdk.TransactionReceipt;
import com.hedera.hashgraph.sdk.account.AccountId;
import com.hedera.hashgraph.sdk.consensus.ConsensusMessageSubmitTransaction;
import com.hedera.hashgraph.sdk.consensus.ConsensusTopicCreateTransaction;
import com.hedera.hashgraph.sdk.consensus.ConsensusTopicId;
import com.hedera.hashgraph.sdk.crypto.ed25519.Ed25519PrivateKey;
import com.hedera.hashgraph.sdk.crypto.ed25519.Ed25519PublicKey;
import com.hedera.hashgraph.sdk.mirror.MirrorClient;
import com.hedera.hashgraph.sdk.mirror.MirrorConsensusTopicQuery;

import io.github.cdimascio.dotenv.Dotenv;
import org.spongycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;

/**
 * An example of an HCS topic that utilizes a submitKey to limit who can submit
 * messages on the topic.
 *
 * Creates a new HCS topic with a single ED25519 submitKey. Subscribes to the
 * topic (no key required). Publishes a number of messages to the topic signed
 * by the submitKey.
 */
public class ConsensusPubSubWithSubmitKey {
	private Client hapiClient;
	private MirrorClient mirrorNodeClient;

	private int messagesToPublish;
	private int messageQueue = 0;

	private ConsensusTopicId topicId;
	private Ed25519PrivateKey submitKey;

	public ConsensusPubSubWithSubmitKey(int messagesToPublish) {
		this.messagesToPublish = messagesToPublish;
		setupHapiClient();
		setupMirrorNodeClient();
	}

	public void topic() throws InterruptedException, HederaStatusException {
		createTopicWithSubmitKey();
		Thread.sleep(15000);
		subscribeToTopic();
	}

	public TransactionReceipt[] execute(String message, boolean responseBack)
			throws InterruptedException, HederaStatusException {
		System.out.println("Size of message  " + message.length());
		return publishMessagesToTopic(message);
	}

	public TransactionReceipt[] execute(byte[] message, boolean responseBack)
			throws InterruptedException, HederaStatusException {
		System.out.println("Size of message  " + message.length);
		return publishMessagesToTopic(message);
	}

	private void setupHapiClient() {
		// Transaction payer's account ID and ED25519 private key.
		AccountId payerId = AccountId.fromString(Objects.requireNonNull(Dotenv.load().get("OPERATOR_ID")));
		String operatorKey = Dotenv.load().get("OPERATOR_KEY");
		Ed25519PrivateKey payerPrivateKey = Ed25519PrivateKey.fromString(operatorKey);

		// Interface used to publish messages on the HCS topic.
		hapiClient = Client.forTestnet();

		// Defaults the operator account ID and key such that all generated transactions
		// will be paid for by this
		// account and be signed by this key
		hapiClient.setOperator(payerId, payerPrivateKey);
	}

	private void setupMirrorNodeClient() {
		// Interface used to subscribe to messages on the HCS topic.
		mirrorNodeClient = new MirrorClient(Objects.requireNonNull(Dotenv.load().get("MIRROR_NODE_ADDRESS")));
	}

	/**
	 * Generate a brand new ED25519 key pair.
	 *
	 * Create a new topic with that key as the topic's submitKey; required to sign
	 * all future ConsensusMessageSubmitTransactions for that topic.
	 *
	 * @throws HederaStatusException
	 */
	private void createTopicWithSubmitKey() throws HederaStatusException {
		// Generate a Ed25519 private, public key pair
		submitKey = Ed25519PrivateKey.generate();
		Ed25519PublicKey submitPublicKey = submitKey.publicKey;

		final TransactionId transactionId = new ConsensusTopicCreateTransaction()
				.setTopicMemo("HCS topic with submit key").setSubmitKey(submitPublicKey).execute(hapiClient);

		topicId = transactionId.getReceipt(hapiClient).getConsensusTopicId();
		System.out.println("Created new topic " + topicId);
	}

	/**
	 * Subscribe to messages on the topic, printing out the received message and
	 * metadata as it is published by the Hedera mirror node.
	 */
	private void subscribeToTopic() {
		new MirrorConsensusTopicQuery().setTopicId(topicId).setStartTime(Instant.ofEpochSecond(0))
				.subscribe(mirrorNodeClient, message -> {
					//System.out.println("Received message:   " + new String(message.message, StandardCharsets.UTF_8)
					//		+ " consensus timestamp: " + message.consensusTimestamp + " topic sequence number: "
					//		+ message.sequenceNumber + " topic running hash: " + Hex.toHexString(message.runningHash));
					messageQueue -= 1;
				},
						// On gRPC error, print the stack trace
						Throwable::printStackTrace);
	}

	/**
	 * Publish a list of messages to a topic, signing each transaction with the
	 * topic's submitKey.
	 * 
	 * @return
	 * 
	 * @throws InterruptedException
	 * @throws HederaStatusException
	 */
	private TransactionReceipt[] publishMessagesToTopic(String message)
			throws InterruptedException, HederaStatusException {
		// Random r = new Random();
		TransactionReceipt[] receipt = new TransactionReceipt[messagesToPublish];
		for (int i = 0; i < messagesToPublish; i++) {
			// String message = "random message " + r.nextLong();

			System.out.println("Publishing message: " + message);
			receipt[i] = new ConsensusMessageSubmitTransaction().setTopicId(topicId).setMessage(message)
					.build(hapiClient)

					// The transaction is automatically signed by the payer.
					// Due to the topic having a submitKey requirement, additionally sign the
					// transaction with that key.
					.sign(submitKey).execute(hapiClient).getReceipt(hapiClient);
			System.out.println("Topic ID           " + topicId);
			System.out.println("Topic Sequence     " + receipt[i].getConsensusTopicSequenceNumber());
			messageQueue += 1;
		}
		return receipt;
	}

	private TransactionReceipt[] publishMessagesToTopic(byte[] message)
			throws InterruptedException, HederaStatusException {
		// Random r = new Random();
		TransactionReceipt[] receipt = new TransactionReceipt[messagesToPublish];
		for (int i = 0; i < messagesToPublish; i++) {
			// String message = "random message " + r.nextLong();

			System.out.println("Publishing message: " + message);

			receipt[i] = new ConsensusMessageSubmitTransaction().setTopicId(topicId).setMessage(message)
					.build(hapiClient)

					// The transaction is automatically signed by the payer.
					// Due to the topic having a submitKey requirement, additionally sign the
					// transaction with that key.
					.sign(submitKey).execute(hapiClient).getReceipt(hapiClient);
			messageQueue += 1;			
			System.out.println("Topic ID           " + topicId);
			System.out.println("Topic Sequence     " + receipt[i].getConsensusTopicSequenceNumber());
		}
		return receipt;
	}

	public String getTopicId() {
		return this.topicId.toString();
	}

	public int GetMessageQueue() {
		return this.messageQueue;
	}
}