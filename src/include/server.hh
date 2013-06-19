#pragma once

#include <list>
#include <string>
#include <thread>
#include <condition_variable>
#include <mutex>

class ClientHandler;

namespace emilpro
{
	class NetworkListener;
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
		// From http://stackoverflow.com/questions/4792449/c0x-has-no-semaphores-how-to-synchronize-threads
		class Semaphore
		{
		private:
			std::mutex m_mutex;
			std::condition_variable m_condition;
			unsigned long m_count;

		public:
			Semaphore()
			: m_count()
			{}

			void notify()
			{
				std::lock_guard<std::mutex> lock(m_mutex);
				++m_count;
				m_condition.notify_one();
			}

			void wait()
			{
				std::unique_lock<std::mutex> lock(m_mutex);
				while(!m_count)
					m_condition.wait(lock);
				--m_count;
			}
		};


		Server();

		~Server();


		void threadMain();

		typedef std::list<IListener *> Listeners_t;

		IConnectionHandler *m_connectionHandler;
		bool m_isConnected;
		Listeners_t m_listeners;
		ClientHandler *m_timestampHolder;
		std::thread *m_thread;
		NetworkListener *m_networkListener;

		bool m_threadStopped;
		std::mutex m_stoppedMutex;
		Semaphore m_threadSemaphore;
	};
}
