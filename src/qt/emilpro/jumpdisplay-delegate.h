#pragma once

#include <jumptargetdisplay.hh>

#include <qitemdelegate.h>

class JumpDisplayDelegate : public QItemDelegate
{
	Q_OBJECT

public:
	JumpDisplayDelegate(bool isForward, QObject *parent = 0);

	void update(const emilpro::InstructionList_t &insnList, unsigned nVisibleInsns);

	void paint(QPainter *painter, const QStyleOptionViewItem &option,
			const QModelIndex &index) const;

	QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const;

private:
	void drawLine(QPainter *painter, int x, int w, QRect *rect) const;

	void drawLineStart(QPainter *painter, bool backward, int x, int w, QRect *rect) const;

	void drawLineEnd(QPainter *painter, bool backward, int x, int w, QRect *rect) const;


	unsigned int m_nLanes;
	unsigned int m_laneWidth;
	emilpro::JumpTargetDisplay m_jumpLanes;
};

