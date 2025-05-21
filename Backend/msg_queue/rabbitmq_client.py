# Backend/agents/common/rabbitmq_client.py
import aio_pika
import json
import logging
from typing import Dict, Any, Callable, Awaitable, Optional

logger = logging.getLogger(__name__)

# Type hint for a consumer callback function
ConsumerCallback = Callable[[Dict[str, Any], str], Awaitable[None]]

class RabbitMQClient:
    _connection: Optional[aio_pika.abc.AbstractRobustConnection] = None
    _channel: Optional[aio_pika.abc.AbstractRobustChannel] = None
    _url: str

    def __init__(self, host: str = "rabbitmq", port: int = 5672, user: str = "guest", password: str = "guest"):
        self._url = f"amqp://{user}:{password}@{host}:{port}/"
        logger.info(f"RabbitMQClient initialized with URL: {self._url}")

    async def connect(self):
        if self._connection is None or self._connection.is_closed:
            logger.info("Connecting to RabbitMQ...")
            self._connection = await aio_pika.connect_robust(self._url)
            self._channel = await self._connection.channel()
            logger.info("Successfully connected to RabbitMQ.")

    async def disconnect(self):
        if self._channel and not self._channel.is_closed:
            await self._channel.close()
            self._channel = None
        if self._connection and not self._connection.is_closed:
            await self._connection.close()
            self._connection = None
        logger.info("Disconnected from RabbitMQ.")

    async def publish_message(
        self,
        queue_name: str,
        message: Dict[str, Any],
        correlation_id: Optional[str] = None,
        reply_to: Optional[str] = None
    ):
        await self.connect() # Ensure connection is open
        if not self._channel:
            raise RuntimeError("RabbitMQ channel not open for publishing.")

        message_body = json.dumps(message).encode('utf-8')
        logger.debug(f"Publishing message to queue '{queue_name}': {message}")

        # Declare the queue if it doesn't exist (ensures messages aren't lost if consumer isn't ready)
        await self._channel.declare_queue(queue_name, durable=True)

        await self._channel.default_exchange.publish(
            aio_pika.Message(
                body=message_body,
                content_type='application/json',
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT, # Make message persistent
                correlation_id=correlation_id,
                reply_to=reply_to
            ),
            routing_key=queue_name,
        )
        logger.info(f"Message published to queue '{queue_name}' with correlation_id: {correlation_id}")

    async def consume_messages(self, queue_name: str, callback: ConsumerCallback):
        await self.connect() # Ensure connection is open
        if not self._channel:
            raise RuntimeError("RabbitMQ channel not open for consuming.")

        logger.info(f"Starting to consume messages from queue: {queue_name}")

        queue = await self._channel.declare_queue(queue_name, durable=True) # Declare durable queue
        await queue.consume(
            lambda message: self._process_consumed_message(message, callback),
            no_ack=False # We will manually acknowledge messages
        )
        # Keep the consumer running
        # In a FastAPI app, this would be part of a background task
        # For agents, the main loop will keep it alive.

    async def _process_consumed_message(self, message: aio_pika.abc.AbstractIncomingMessage, callback: ConsumerCallback):
        async with message.process():
            try:
                body = message.body.decode('utf-8')
                data = json.loads(body)
                correlation_id = message.correlation_id or "N/A"
                reply_to = message.reply_to

                logger.info(f"Received message from '{message.routing_key}' (Corr ID: {correlation_id}, Reply To: {reply_to}): {data}")

                await callback(data, correlation_id) # Execute the consumer's callback

            except json.JSONDecodeError:
                logger.error(f"Failed to decode JSON from message: {message.body.decode('utf-8')}")
            except Exception as e:
                logger.error(f"Error processing message from queue '{message.routing_key}' (Corr ID: {correlation_id}): {e}", exc_info=True)
                # Requeue message if processing fails, depends on desired behavior
                # message.reject(requeue=True)
            finally:
                pass # message.process() handles ack/nack