#include "jumpdisplay-delegate.h"

#include <qpainter.h>

using namespace emilpro;

JumpDisplayDelegate::JumpDisplayDelegate(bool isForward, QObject* parent) :
	m_nLanes(4),
	m_laneWidth(80 / m_nLanes),
	m_jumpLanes(isForward, m_nLanes)
{
}

void JumpDisplayDelegate::update(const InstructionList_t& insnList,
		unsigned nVisibleInsns)
{
	m_jumpLanes.calculateLanes(insnList, nVisibleInsns);
}

QSize JumpDisplayDelegate::sizeHint(const QStyleOptionViewItem& option,
		const QModelIndex& index) const
{
	QRect r = option.rect;

	return QSize(80, r.height());
}

void JumpDisplayDelegate::paint(QPainter* painter,
		const QStyleOptionViewItem& option, const QModelIndex& index) const
{
	JumpTargetDisplay::LaneValue_t lanes[m_nLanes];
	QColor color[m_nLanes];

	color[0] = QColor(Qt::green);
	color[1] = QColor(Qt::cyan);
	color[2] = QColor(Qt::red);
	color[3] = QColor(Qt::magenta);

	int row = index.row();
	QRect r = option.rect;

	if (!m_jumpLanes.getLanes(row, lanes))
		memset(lanes, JumpTargetDisplay::LANE_NONE, sizeof(lanes));

	//r.setWidth(m_laneWidth);
	for (unsigned lane = 0; lane < m_nLanes; lane++) {
		int x = r.x() + m_laneWidth * lane;
		int w = r.width() / m_nLanes;

		QPen pen(color[lane], Qt::SolidLine);
		pen.setWidth(2);

		painter->setPen(pen);
		painter->setBrush(QBrush(color[lane]));

		switch (lanes[lane])
		{
		case JumpTargetDisplay::LANE_LINE:
			drawLine(painter, x, w, &r);
			break;
		case JumpTargetDisplay::LANE_END_DOWN:
			drawLineEnd(painter, false, x, w, &r);
			break;
		case JumpTargetDisplay::LANE_END_UP:
			drawLineEnd(painter, true, x, w, &r);
			break;
		case JumpTargetDisplay::LANE_START_DOWN:
			drawLineStart(painter, false, x, w, &r);
			break;
		case JumpTargetDisplay::LANE_START_UP:
			drawLineStart(painter, true, x, w, &r);
			break;
		case JumpTargetDisplay::LANE_START_LONG_DOWN:
			pen.setStyle(Qt::DotLine);
			painter->setPen(pen);
			drawLineStart(painter, false, x, w, &r);
			break;
		case JumpTargetDisplay::LANE_START_LONG_UP:
			pen.setStyle(Qt::DotLine);
			painter->setPen(pen);
			drawLineStart(painter, true, x, w, &r);
			break;
		case JumpTargetDisplay::LANE_END_LONG_DOWN:
			pen.setStyle(Qt::DotLine);
			painter->setPen(pen);
			drawLineEnd(painter, false, x, w, &r);
			break;
		case JumpTargetDisplay::LANE_END_LONG_UP:
			pen.setStyle(Qt::DotLine);
			painter->setPen(pen);
			drawLineEnd(painter, true, x, w, &r);
			break;
		default:
			break;
		}

	}
}

void JumpDisplayDelegate::drawLine(QPainter* painter,
		int x, int w, QRect* rect) const
{
	painter->drawLine(x + w / 2, rect->y(),
			x + w / 2, rect->y() + rect->height());
}

void JumpDisplayDelegate::drawLineStart(QPainter* painter, bool backward, int x,
		int w, QRect* rect) const
{
	int startY = rect->y() + rect->height() / 2;
	int endY = backward ? rect->y() : rect->y() + rect->height();
	int startX = x + w / 2;

	painter->drawEllipse(startX - 3, startY - 3, 6, 6);
	painter->drawLine(startX, startY, startX, endY);
}

void JumpDisplayDelegate::drawLineEnd(QPainter* painter, bool backward, int x,
		int w, QRect* rect) const
{
	int endY = rect->y() + rect->height() / 2;
	int startY = backward ? rect->y() + rect->height() : rect->y();
	int startX = x + w / 2;
	int endX = backward ? rect->x() + rect->width() : rect->x();
	int arrowDir = backward ? -1 : 1;
	QPolygon polygon;

	painter->drawLine(startX, startY, startX, endY);

	polygon << QPoint(startX, endY)
			<< QPoint(endX, endY)
			<< QPoint(endX + 5 * arrowDir, endY - 5)
			<< QPoint(endX + 5 * arrowDir, endY + 5)
			<< QPoint(endX, endY);

	painter->drawPolygon(polygon);
}
