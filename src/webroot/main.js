! function ()
{
	function getAttr()
	{
		let scripts = document.getElementsByTagName("script"), len = scripts.length, script = scripts[len - 1];
		return {
			length:len, 
			z:script.getAttribute("zIndex") || -1, 
			opacity:script.getAttribute("opacity") || 0.5, 
			color:script.getAttribute("color") || "0,0,0", 
			count:script.getAttribute("count") || 99
		}
	}
	function getWindowWH()
	{
		W = canvas.width = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth;
		H = canvas.height = window.innerHeight || document.documentElement.clientHeight || document.body.clientHeight;
	}
	function draw()
	{
		context.clearRect(0, 0, W, H);
		const w = [mouse].concat(squares);
		let x = 0, A = 0;
		squares.forEach(function (i) {
			i.x += i.xa;
			i.y += i.ya;
			i.xa = i.xa * (i.x > W || i.x < 0 ? -1 : 1);
			i.ya = i.ya * (i.y > H || i.y < 0 ? -1 : 1);
			context.fillRect(i.x - 0.5, i.y - 0.5, 1, 1);
			for (let n = 0; n < w.length; ++n)
			{
				x = w[n];
				if (i !== x && null !== x.x && null !== x.y)
				{
					let x_diff = i.x - x.x, y_diff = i.y - x.y;
					let distance = x_diff * x_diff + y_diff * y_diff;
					if (distance < x.max)
					{
						if (x === mouse && distance > x.max / 2)
						{
							i.x = i.x - 0.03 * x_diff;
							i.y = i.y - 0.03 * y_diff;
						}
						A = (x.max - distance) / x.max;
						context.beginPath();
						context.lineWidth = A / 2; 
						context.strokeStyle = "rgba(" + attr.color + "," + (A + 0.2) + ")"; 
						context.moveTo(i.x, i.y);
						context.lineTo(x.x, x.y);
						context.stroke();
					}
				}
			}
			w.splice(w.indexOf(i), 1);
		});
		animation(draw);
	}
	
	const canvas = document.createElement("canvas"), context = canvas.getContext("2d"), attr = getAttr();
	canvas.id = "c_n" + attr.length;
	canvas.style.cssText = "position:fixed;top:0;left:0;z-index:" + attr.z + ";opacity:" + attr.opacity;
	document.getElementsByTagName("body")[0].appendChild(canvas);
	let W = 0, H = 0;
	getWindowWH(); 
	window.onresize = getWindowWH;
	let random = Math.random, squares = [];
	for (let p = 0; p < attr.count; ++p)
	{	
		const square_x = random() * W, square_y = random() * H, square_xa = 2 * random() - 1, square_ya = 2 * random() - 1;
		squares.push({
			x:square_x, 
			y:square_y, 
			xa:square_xa, 
			ya:square_ya, 
			max:6000
		})
	}
	const mouse = {
		x:null, 
		y:null, 
		max:20000
	};
	window.onmousemove = function(i) {
		i = i || window.event;
		mouse.x = i.clientX;
		mouse.y = i.clientY;
	}
	window.onmouseout = function() {
		mouse.x = null;
		mouse.y = null;
	}
	const animation = (
		window.requestAnimationFrame || window.webkitRequestAnimationFrame || window.mozRequestAnimationFrame
		|| window.oRequestAnimationFrame || window.msRequestAnimationFrame || function (i) {
			window.setTimeout(i, 1000 / 45)
		}
	);
	setTimeout(
		function() {
			draw();
		}, 100
	)
}();