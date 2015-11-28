#!/usr/bin/python
# -*- coding: utf-8 -*-


#Модули
import nmap;
import argparse;
import threading;
import queue;
import datetime;
import os;


#Функция проверки существования файла
def OnFile(FileName):
	if os.path.exists(FileName):
		return True;
	else:
		return False;

#Процедура скана (многопоточная), принимает номер потока и очередь имя файла и блокировку
def Scan(i, q, FOutputFileName, Lock, port):
	#Бесконечный цикл
	while True:
		#Пустой список с адресами
		Adress = [];
		#Берем из очереди строку (те диапазон айпишников)
		ip = q.get();
		#Пишем что поток номер такой взял такой диапазон
		print ("\x1b[37m" +str(datetime.datetime.now()) + " - Thread " + str(i) + " Scaning " + ip[:-1] + " - " + str(q.qsize()) + "\x1b[0m");
		#Создаем сканер нмап
		nm = nmap.PortScanner();
		#Начинаем скан
		nm.scan(ip, str(port));
		#Проходим по всем хостам
		for host in nm.all_hosts():
			#Если порт открыт
			if (nm[host]['tcp'][int(port)]['state'] == 'open'):
				#Добовляем айпи в список
				Adress.append(host);
		#Если список больше 0 то
		if (len(Adress) != 0):
			#Такойто поток насканил столько хостов
			print("\x1b[32m" + str(datetime.datetime.now()) + " - Thread " + str(i) + " Ip " + str(len(Adress)) + "\x1b[0m");
			#Захватить блокировку
			Lock.acquire(1);
			#Открываем файл для дозаписи
			OutputFile = open(FOutputFileName, 'a');
			#Цикл по списку айпишников
			for ad in Adress:
				#Записывем айпишники в файл
				OutputFile.write(ad + '\n');
			#Закрываем файл
			OutputFile.close();
			#Отпустить блокировку
			Lock.release();
		#Ждем конца очереди
		q.task_done();

def Main():
	#Создаем очередь
	IPList = queue.Queue();
	#Создаем парсер
	parse = argparse.ArgumentParser(description='Сканер')
	#Добавляем опцию, путь к файлу паролей
	parse.add_argument('-f', action='store', dest='IP', help='Путь к файлу с айпишниками, пример: \'IP.txt\'');
	parse.add_argument('-t', action='store', dest='Thread', help='Количество потоков');
	parse.add_argument('-p', action='store', dest='Port', help='Порт для скана');
	parse.add_argument('-o', action='store', dest='OutputFileName', help='Имя файла вывода');
	#Получаем аргументы
	args = parse.parse_args();
	#Если аргументов нет то
	if (args.IP == None) or (args.Thread == None) or (args.OutputFileName == None) or (args.Port == None):
		#Выводим хэлп
		print (parse.print_help());
		#Выход
		exit();
	#Иначе, если аргументы есть то
	else:
		#Проверка на существование файлов
		if (OnFile(args.IP) != True):
			print ("\x1b[31m" +str(datetime.datetime.now()) + " - IP List file no found\x1b[0m");
			exit();
		if (OnFile(args.OutputFileName) != True):
			print ("\x1b[31m" +str(datetime.datetime.now()) + " - Output file no found\x1b[0m");
			exit();
		#Блокировка
		screenLock = threading.Lock();
		#Создаем потоки
		for i in range(int(args.Thread)):
			worker = threading.Thread(target=Scan, args=(i, IPList, args.OutputFileName, screenLock, args.Port));
			worker.setDaemon(True);
			worker.start();
		#чтение из файла
		IpFile = open(args.IP, "rU");
		#построчно читаем файл и выводим на экран
		for line in IpFile.readlines():
			#Добовляем в очередь ип из списка 
			IPList.put(line);
		print ("\x1b[34m" +str(datetime.datetime.now()) + " - Scan Starting...\x1b[0m");
		IPList.join();
		print ("\x1b[34m" + str(datetime.datetime.now()) + " - Scan Done\x1b[0m");


if __name__=="__main__":
	Main();
