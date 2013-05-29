#pragma once

#include <list>
#include <string>
#include <thread>

class ClientHandler;

namespace emilpro
{
	class Server
	{
	public:
		class IListener
		{
		public:
			virtual ~IListener()
			{
			}

			/**
			 * Callback with
			 */
			virtual void onConnectResult(bool connected, const std::string &status) = 0;

			virtual void onXml(const std::string &xml) = 0;
		};

		class IConnectionHandler
		{
		public:
			virtual ~IConnectionHandler()
			{
			}

			virtual bool setup(void) = 0;

			virtual std::string talk(const std::string &xml) = 0;
		};

		void registerListener(IListener &listener);

		void unregisterListener(IListener &listener);

		void setConnectionHandler(IConnectionHandler &handler);

		bool connect();

		void stop();

		bool sendXml(std::string &what);


		void destroy();

		static Server &instance();

	private:
		Server();

		~Server();


		void threadMain();

		typedef std::list<IListener *> Listeners_t;

		IConnectionHandler *m_connectionHandler;
		bool m_isConnected;
		Listeners_t m_listeners;
		ClientHandler *m_timestampHolder;
		std::thread *m_thread;
	};
}
